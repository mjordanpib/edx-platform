"""
Tests for EmbargoMiddleware
"""

import unittest

from django.conf import settings
from django.test.utils import override_settings
from django.core.cache import cache
import ddt

from xmodule.modulestore.tests.factories import CourseFactory
from xmodule.modulestore.tests.django_utils import (
    ModuleStoreTestCase, mixed_store_config
)

from embargo.models import RestrictedCourse, Country, CountryAccessRule

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
