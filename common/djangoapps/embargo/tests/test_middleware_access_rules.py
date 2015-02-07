"""
Tests for EmbargoMiddleware with CountryAccessRules
"""

import unittest
from mock import patch
import ddt

from django.core.urlresolvers import reverse
from django.conf import settings
from django.core.cache import cache as django_cache

from util.testing import UrlResetMixin
from student.tests.factories import UserFactory
from xmodule.modulestore.tests.factories import CourseFactory
from xmodule.modulestore.tests.django_utils import (
    ModuleStoreTestCase, mixed_store_config
)
from config_models.models import cache as config_cache

from embargo.models import RestrictedCourse, IPFilter
from embargo.test_utils import restrict_course


# Since we don't need any XML course fixtures, use a modulestore configuration
# that disables the XML modulestore.
MODULESTORE_CONFIG = mixed_store_config(settings.COMMON_TEST_DATA_ROOT, {}, include_xml=False)


@ddt.ddt
@unittest.skipUnless(settings.ROOT_URLCONF == 'lms.urls', 'Test only valid in lms')
class EmbargoMiddlewareAccessTests(UrlResetMixin, ModuleStoreTestCase):
    """Tests of embargo middleware country access rules.

    There are detailed unit tests for the rule logic in
    `test_api.py`; here, we're mainly testing the integration
    with middleware

    """
    USERNAME = 'fred'
    PASSWORD = 'secret'

    @patch.dict(settings.FEATURES, {'ENABLE_COUNTRY_ACCESS': True})
    def setUp(self):
        super(EmbargoMiddlewareAccessTests, self).setUp('embargo')
        self.user = UserFactory(username=self.USERNAME, password=self.PASSWORD)
        self.course = CourseFactory.create()
        self.client.login(username=self.USERNAME, password=self.PASSWORD)

        self.courseware_url = reverse(
            'course_root',
            kwargs={'course_id': unicode(self.course.id)}
        )
        self.non_courseware_url = reverse('dashboard')

        # Clear the cache to avoid interference between tests
        django_cache.clear()
        config_cache.clear()

    @patch.dict(settings.FEATURES, {'ENABLE_COUNTRY_ACCESS': True})
    def test_blocked(self):
        with restrict_course(self.course.id, access_point='courseware') as redirect_url:
            response = self.client.get(self.courseware_url)
            self.assertRedirects(response, redirect_url)

    @patch.dict(settings.FEATURES, {'ENABLE_COUNTRY_ACCESS': True})
    def test_allowed(self):
        # Add the course to the list of restricted courses
        # but don't create any access rules
        RestrictedCourse.objects.create(course_key=self.course.id)

        # Expect that we can access courseware
        response = self.client.get(self.courseware_url)
        self.assertEqual(response.status_code, 200)

    @patch.dict(settings.FEATURES, {'ENABLE_COUNTRY_ACCESS': True})
    def test_non_courseware_url(self):
        with restrict_course(self.course.id):
            response = self.client.get(self.non_courseware_url)
            self.assertEqual(response.status_code, 200)

    @patch.dict(settings.FEATURES, {'ENABLE_COUNTRY_ACCESS': True})
    @ddt.data(
        # request_ip, blacklist, whitelist, allow_access
        ('173.194.123.35', ['173.194.123.35'], [], False),
        ('173.194.123.35', ['173.194.0.0/16'], [], False),
        ('173.194.123.35', ['127.0.0.0/32', '173.194.0.0/16'], [], False),
        ('173.195.10.20', ['173.194.0.0/16'], [], True),
        ('173.194.123.35', ['173.194.0.0/16'], ['173.194.0.0/16'], False),
        ('173.194.123.35', [], ['173.194.0.0/16'], True),
        ('192.178.2.3', [], ['173.194.0.0/16'], True),
    )
    @ddt.unpack
    def test_ip_access_rules(self, request_ip, blacklist, whitelist, allow_access):
        # Set up the IP rules
        IPFilter.objects.create(
            blacklist=", ".join(blacklist),
            whitelist=", ".join(whitelist),
        )

        # Check that access is enforced
        response = self.client.get(
            self.non_courseware_url,
            HTTP_X_FORWARDED_FOR=request_ip,
            REMOTE_ADDR=request_ip
        )

        if allow_access:
            self.assertEqual(response.status_code, 200)
        else:
            redirect_url = reverse(
                'embargo_blocked_message',
                kwargs={
                    'access_point': 'courseware',
                    'message_key': 'embargo'
                }
            )
            self.assertRedirects(response, redirect_url)

    @patch.dict(settings.FEATURES, {'ENABLE_COUNTRY_ACCESS': True})
    def test_whitelist_ip_skips_country_access_checks(self):
        # Whitelist an IP address
        IPFilter.objects.create(
            whitelist="192.168.10.20"
        )

        # Set up country access rules so the user would
        # be restricted from the course.
        with restrict_course(self.course.id):
            # Make a request from the whitelisted IP address
            response = self.client.get(
                self.non_courseware_url,
                HTTP_X_FORWARDED_FOR="192.168.10.20",
                REMOTE_ADDR="192.168.10.20"
            )

        # Expect that we were still able to access the page,
        # even though we would have been blocked by country
        # access rules.
        self.assertEqual(response.status_code, 200)
