"""
Tests for EmbargoMiddleware
"""

import mock
import unittest
import pygeoip
import ddt

from django.conf import settings
from django.test.utils import override_settings
from django.core.cache import cache
from django.db import connection, transaction

from student.tests.factories import UserFactory
from xmodule.modulestore.tests.factories import CourseFactory
from xmodule.modulestore.tests.django_utils import (
    ModuleStoreTestCase, mixed_store_config
)

from embargo.models import (
    RestrictedCourse, Country,
    CountryAccessRule,
    WHITE_LIST, BLACK_LIST
)

from util.testing import UrlResetMixin
from embargo import api as embargo_api
from embargo.exceptions import InvalidAccessPoint
from mock import patch


# Since we don't need any XML course fixtures, use a modulestore configuration
# that disables the XML modulestore.
MODULESTORE_CONFIG = mixed_store_config(settings.COMMON_TEST_DATA_ROOT, {}, include_xml=False)


@ddt.ddt
@override_settings(MODULESTORE=MODULESTORE_CONFIG)
@unittest.skipUnless(settings.ROOT_URLCONF == 'lms.urls', 'Test only valid in lms')
class EmbargoCheckAccessApiTests(ModuleStoreTestCase):
    """Test the embargo API calls to determine whether a user has access. """

    def setUp(self):
        super(EmbargoCheckAccessApiTests, self).setUp()
        self.course = CourseFactory.create()
        self.user = UserFactory.create()
        self.restricted_course = RestrictedCourse.objects.create(course_key=self.course.id)
        Country.objects.create(country='US')
        Country.objects.create(country='IR')
        Country.objects.create(country='CU')

        # Clear the cache to prevent interference between tests
        cache.clear()

    @ddt.data(
        # IP country, profile_country, blacklist, whitelist, allow_access
        ('US', None, [], [], True),
        ('IR', None, ['IR', 'CU'], [], False),
        ('US', 'IR', ['IR', 'CU'], [], False),
        ('IR', 'IR', ['IR', 'CU'], [], False),
        ('US', None, [], ['US'], True),
        ('IR', None, [], ['US'], False),
        ('US', 'IR', [], ['US'], False),
    )
    @ddt.unpack
    def test_country_access_rules(self, ip_country, profile_country, blacklist, whitelist, allow_access):
        # Configure the access rules
        for whitelist_country in whitelist:
            CountryAccessRule.objects.create(
                rule_type=WHITE_LIST,
                restricted_course=self.restricted_course,
                country=Country.objects.get(country=whitelist_country)
            )

        for blacklist_country in blacklist:
            CountryAccessRule.objects.create(
                rule_type=BLACK_LIST,
                restricted_course=self.restricted_course,
                country=Country.objects.get(country=blacklist_country)
            )

        # Configure the user's profile country
        if profile_country is not None:
            self.user.profile.country = profile_country
            self.user.profile.save()

        # Appear to make a request from an IP in a particular country
        with mock.patch.object(pygeoip.GeoIP, 'country_code_by_addr') as mock_ip:
            mock_ip.return_value = ip_country

            # Call the API.  Note that the IP address we pass in doesn't
            # matter, since we're injecting a mock for geo-location
            result = embargo_api.check_course_access(self.user, '0.0.0.0', self.course.id)

        # Verify that the access rules were applied correctly
        self.assertEqual(result, allow_access)

    def test_course_not_restricted(self):
        # No restricted course model for this course key,
        # so all access checks should be skipped.
        unrestricted_course = CourseFactory.create()
        with self.assertNumQueries(1):
            embargo_api.check_course_access(self.user, '0.0.0.0', unrestricted_course.id)

        # The second check should require no database queries
        with self.assertNumQueries(0):
            embargo_api.check_course_access(self.user, '0.0.0.0', unrestricted_course.id)

    def test_ip_v6(self):
        # Test the scenario that will go through every check
        # (restricted course, but pass all the checks)
        result = embargo_api.check_course_access(self.user, 'FE80::0202:B3FF:FE1E:8329', self.course.id)
        self.assertTrue(result)

    @mock.patch.dict(settings.FEATURES, {'ENABLE_COUNTRY_ACCESS': True})
    def test_profile_country_db_null(self):
        # Django country fields treat NULL values inconsistently.
        # When saving a profile with country set to None, Django saves an empty string to the database.
        # However, when the country field loads a NULL value from the database, it sets
        # `country.code` to `None`.  This caused a bug in which country values created by
        # the original South schema migration -- which defaulted to NULL -- caused a runtime
        # exception when the embargo middleware treated the value as a string.
        # In order to simulate this behavior, we can't simply set `profile.country = None`.
        # (because when we save it, it will set the database field to an empty string instead of NULL)
        query = "UPDATE auth_userprofile SET country = NULL WHERE id = %s"
        connection.cursor().execute(query, [str(self.user.profile.id)])
        transaction.commit_unless_managed()

        # Verify that we can check the user's access without error
        result = embargo_api.check_course_access(self.user, '0.0.0.0', self.course.id)
        self.assertTrue(result)

    def test_caching(self):
        # Test the scenario that will go through every check
        # (restricted course, but pass all the checks)
        # This is the worst case, so it will hit all of the
        # caching code.
        with self.assertNumQueries(3):
            embargo_api.check_course_access(self.user, '0.0.0.0', self.course.id)

        with self.assertNumQueries(0):
            embargo_api.check_course_access(self.user, '0.0.0.0', self.course.id)


@ddt.ddt
@override_settings(MODULESTORE=MODULESTORE_CONFIG)
@unittest.skipUnless(settings.ROOT_URLCONF == 'lms.urls', 'Test only valid in lms')
class EmbargoMessageUrlApiTests(UrlResetMixin, ModuleStoreTestCase):
    """Test the embargo API calls for retrieving the blocking message URLs. """

    @patch.dict(settings.FEATURES, {'ENABLE_COUNTRY_ACCESS': True})
    def setUp(self):
        super(EmbargoMessageUrlApiTests, self).setUp('embargo')
        self.course = CourseFactory.create()

    def tearDown(self):
        cache.clear()

    @ddt.data(
        ('enrollment', '/embargo/blocked-message/enrollment/embargo/'),
        ('courseware', '/embargo/blocked-message/courseware/embargo/')
    )
    @ddt.unpack
    def test_message_url_path(self, access_point, expected_url_path):
        self._restrict_course(self.course.id)

        # Retrieve the URL to the blocked message page
        url_path = embargo_api.message_url_path(self.course.id, access_point)
        self.assertEqual(url_path, expected_url_path)

    def test_message_url_path_caching(self):
        self._restrict_course(self.course.id)

        # The first time we retrieve the message, we'll need
        # to hit the database.
        with self.assertNumQueries(2):
            embargo_api.message_url_path(self.course.id, "enrollment")

        # The second time, we should be using cached values
        with self.assertNumQueries(0):
            embargo_api.message_url_path(self.course.id, "enrollment")

    @ddt.data('enrollment', 'courseware')
    def test_message_url_path_no_restrictions_for_course(self, access_point):
        # No restrictions for the course
        url_path = embargo_api.message_url_path(self.course.id, access_point)

        # Use a default path
        self.assertEqual(url_path, '/embargo/blocked-message/courseware/default/')

    def test_invalid_access_point(self):
        with self.assertRaises(InvalidAccessPoint):
            embargo_api.message_url_path(self.course.id, "invalid")

    def test_message_url_stale_cache(self):
        # Retrieve the URL once, populating the cache with the list
        # of restricted courses.
        self._restrict_course(self.course.id)
        embargo_api.message_url_path(self.course.id, 'courseware')

        # Delete the restricted course entry
        RestrictedCourse.objects.get(course_key=self.course.id).delete()

        # Clear the message URL cache
        message_cache_key = (
            'embargo.message_url_path.courseware.{course_key}'
        ).format(course_key=self.course.id)
        cache.delete(message_cache_key)

        # Try again.  Even though the cache results are stale,
        # we should still get a valid URL.
        url_path = embargo_api.message_url_path(self.course.id, 'courseware')
        self.assertEqual(url_path, '/embargo/blocked-message/courseware/default/')

    def _restrict_course(self, course_key):
        """Restrict the user from accessing the course. """
        country = Country.objects.create(country='us')
        restricted_course = RestrictedCourse.objects.create(
            course_key=course_key,
            enroll_msg_key='embargo',
            access_msg_key='embargo'
        )
        CountryAccessRule.objects.create(
            restricted_course=restricted_course,
            rule_type=BLACK_LIST,
            country=country
        )
