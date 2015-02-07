"""
Tests for EmbargoMiddleware with CountryAccessRules
"""

import unittest
from mock import patch
import ddt

from django.core.urlresolvers import reverse
from django.conf import settings
from django.core.cache import cache

from util.testing import UrlResetMixin
from student.tests.factories import UserFactory
from xmodule.modulestore.tests.factories import CourseFactory
from xmodule.modulestore.tests.django_utils import (
    ModuleStoreTestCase, mixed_store_config
)

from embargo.models import RestrictedCourse
from embargo.test_utils import restrict_course


# Since we don't need any XML course fixtures, use a modulestore configuration
# that disables the XML modulestore.
MODULESTORE_CONFIG = mixed_store_config(settings.COMMON_TEST_DATA_ROOT, {}, include_xml=False)


@ddt.ddt
@unittest.skipUnless(settings.ROOT_URLCONF == 'lms.urls', 'Test only valid in lms')
class EmbargoMiddlewareCountryAccessTests(UrlResetMixin, ModuleStoreTestCase):
    """Tests of embargo middleware country access rules.

    There are detailed unit tests for the rule logic in
    `test_api.py`; here, we're mainly testing the integration
    with middleware

    """
    USERNAME = 'fred'
    PASSWORD = 'secret'

    @patch.dict(settings.FEATURES, {'ENABLE_COUNTRY_ACCESS': True})
    def setUp(self):
        super(EmbargoMiddlewareCountryAccessTests, self).setUp('embargo')
        self.user = UserFactory(username=self.USERNAME, password=self.PASSWORD)
        self.course = CourseFactory.create()
        self.client.login(username=self.USERNAME, password=self.PASSWORD)

        self.courseware_url = reverse(
            'course_root',
            kwargs={'course_id': unicode(self.course.id)}
        )
        self.non_courseware_url = reverse('dashboard')

        # Clear the cache to avoid interference between tests
        cache.clear()

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
