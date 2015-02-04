""" API implementation for course-oriented interactions. """

import logging

from django.http import Http404
from rest_framework.authentication import OAuth2Authentication, SessionAuthentication
from rest_framework.generics import RetrieveAPIView, ListAPIView
from xmodule.modulestore.django import modulestore
from opaque_keys.edx.keys import CourseKey
from openedx.core.lib.api.permissions import IsAuthenticatedOrDebug
from openedx.core.lib.api.serializers import PaginationSerializer

from courseware import courses
from course_api.v0 import serializers


log = logging.getLogger(__name__)


class AuthMixin(object):
    authentication_classes = (SessionAuthentication, OAuth2Authentication,)
    permission_classes = (IsAuthenticatedOrDebug,)


class CourseViewMixin(object):
    """
    Mixin for views dealing with course content.
    """
    lookup_field = 'course_id'

    def get_serializer_context(self):
        """
        Supplies a course_id to the serializer.
        """
        context = super(CourseViewMixin, self).get_serializer_context()
        context['course_id'] = self.kwargs.get('course_id')
        return context

    def get_course_or_404(self, request, course_id):  # pylint: disable=unused-argument
        """
        Retrieves the specified course, or raises an Http404 error if it does not exist.
        """
        try:
            course_key = CourseKey.from_string(course_id)
            return courses.get_course(course_key)
        except ValueError:
            raise Http404


class CourseList(CourseViewMixin, AuthMixin, ListAPIView):
    """
    **Use Case**

        CourseList returns paginated list of courses in the edX Platform. The list can be
        filtered by course_id

    **Example Request**

          GET /
          GET /?course_id={course_id1},{course_id2}

    **Response Values**

        * category: The type of content. In this case, the value is always "course".

        * name: The name of the course.

        * uri: The URI to use to get details of the course.

        * course: The course number.

        * due:  The due date. For courses, the value is always null.

        * org: The organization specified for the course.

        * id: The unique identifier for the course.
    """
    paginate_by = 10
    paginate_by_param = 'page_size'
    pagination_serializer_class = PaginationSerializer
    serializer_class = serializers.CourseSerializer

    def get_queryset(self):
        course_ids = self.request.QUERY_PARAMS.get('course_id', None)

        course_descriptors = []
        if course_ids:
            course_ids = course_ids.split(',')
            for course_id in course_ids:
                course_key = CourseKey.from_string(course_id)
                course_descriptor = courses.get_course(course_key)
                course_descriptors.append(course_descriptor)
        else:
            course_descriptors = modulestore().get_courses()

        results = course_descriptors

        # Sort the results in a predictable manner.
        results.sort(key=lambda x: x.id)

        return results


class CourseDetail(CourseViewMixin, AuthMixin, RetrieveAPIView):
    """
    **Use Case**

        CourseDetail returns details for a course.

        The optional **depth** parameter that allows clients to get child content down to the specified tree level.

    **Example requests**:

        GET /{course_id}/

        GET /{course_id}/?depth=2

    **Response Values**

        * category: The type of content.

        * name: The name of the course.

        * uri: The URI to use to get details of the course.

        * course: The course number.

        * content: When the depth parameter is used, a collection of child
          course content entities, such as chapters, sequentials, and
          components.

        * due:  The due date. For courses, the value is always null.

        * org: The organization specified for the course.

        * id: The unique identifier for the course.
    """

    serializer_class = serializers.CourseSerializer

    def get_object(self, queryset=None):
        course_id = self.kwargs.get('course_id')
        request = self.request
        course_descriptor = self.get_course_or_404(request, course_id)
        return course_descriptor


class CourseStructure(CourseViewMixin, AuthMixin, RetrieveAPIView):
    serializer_class = serializers.CourseStructureSerializer

    def get_object(self, queryset=None):
        course_id = self.kwargs.get('course_id')
        course_key = CourseKey.from_string(course_id)
        _modulestore = modulestore()

        # Ensure the course exists before doing any processing
        if not _modulestore.has_course(course_key):
            raise Http404

        return _modulestore.get_course_structure(course_key)


class CourseGradingPolicy(AuthMixin, ListAPIView):
    """
    **Use Case**

        Retrieves course grading policy.

    **Example requests**:

        GET /{course_id}/grading_policy/

    **Response Values**

        * assignment_type: The type of the assignment (e.g. Exam, Homework). Note: These values are course-dependent.
          Do not make any assumptions based on assignment type.

        * count: Number of assignments of the type.

        * dropped: Number of assignments of the type that are dropped.

        * weight: Effect of the assignment type on grading.
    """

    serializer_class = serializers.GradingPolicySerializer
    allow_empty = False

    def get_queryset(self):
        course_id = self.kwargs.get('course_id')
        course_key = CourseKey.from_string(course_id)

        course = modulestore().get_course(course_key)

        # Ensure the course exists
        if not course:
            raise Http404

        # Return the raw data. The serializer will handle the field mappings.
        return course.raw_grader
