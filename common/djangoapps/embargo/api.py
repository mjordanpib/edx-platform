"""
The Python API layer of the country access settings. Essentially the middle tier of the project, responsible for all
business logic that is not directly tied to the data itself.

This API is exposed via the middleware(emabargo/middileware.py) layer but may be used directly in-process.

"""
import logging
import pygeoip

from django.core.urlresolvers import reverse
from django.core.cache import cache
from django.conf import settings

from embargo.models import CountryAccessRule, RestrictedCourse
from embargo.exceptions import InvalidAccessPoint


log = logging.getLogger(__name__)


def check_course_access(user, ip_address, course_key):
    """
    Check is the user with this ip_address has access to the given course

    Params:
        user (User): Currently logged in user object
        ip_address (str): The ip_address of user
        course_key (CourseLocator): CourseLocator object the user is trying to access

    Returns:
        Boolean: True if the user has access to the course; False otherwise

    """
    course_is_restricted = RestrictedCourse.is_restricted_course(course_key)
    # If they're trying to access a course that cares about embargoes

    # If course is not restricted then return immediately return True
    # no need for further checking
    if not course_is_restricted:
        return True

    # Retrieve the country code from the IP address
    # and check it against the allowed countries list for a course
    user_country_from_ip = _country_code_from_ip(ip_address)

    # if user country has access to course return True
    if not CountryAccessRule.check_country_access(course_key, user_country_from_ip):
        return False

    # Retrieve the country code from the user profile.
    user_country_from_profile = _get_user_country_from_profile(user)

    # if profile country has access return True
    if not CountryAccessRule.check_country_access(course_key, user_country_from_profile):
        return False

    return True


def message_url_path(course_key, access_point):
    """Determine the URL path for the message explaining why the user was blocked.

    This is configured per-course.  See `RestrictedCourse` in the `embargo.models`
    module for more details.

    Arguments:
        course_key (CourseKey): The location of the course.
        access_point (str): How the user was trying to access the course.
            Can be either "enrollment" or "courseware".

    Returns:
        unicode: The URL path to a page explaining why the user was blocked.

    Raises:
        InvalidAccessPoint: Raised if access_point is not a supported value.

    """
    if access_point not in ['enrollment', 'courseware']:
        raise InvalidAccessPoint(access_point)

    # First check the cache to see if we already have
    # a URL for this (course_key, access_point) tuple
    cache_key = u"embargo.message_url_path.{access_point}.{course_key}".format(
        access_point=access_point,
        course_key=course_key
    )
    url = cache.get(cache_key)

    # If there's a cache miss, we'll need to retrieve the message
    # configuration from the database
    if url is None:
        url = _get_message_url_path_from_db(course_key, access_point)
        cache.set(cache_key, url)

    return url


def _get_user_country_from_profile(user):
    """
    Check whether the user is embargoed based on the country code in the user's profile.

    Args:
        user (User): The user attempting to access courseware.

    Returns:
        user country from profile.

    """
    cache_key = u'user.{user_id}.profile.country'.format(user_id=user.id)
    profile_country = cache.get(cache_key)
    if profile_country is None:
        profile = getattr(user, 'profile', None)
        if profile is not None and profile.country.code is not None:
            profile_country = profile.country.code.upper()
        else:
            profile_country = ""
        cache.set(cache_key, profile_country)

    return profile_country


def _country_code_from_ip(ip_addr):
    """
    Return the country code associated with an IP address.
    Handles both IPv4 and IPv6 addresses.

    Args:
        ip_addr (str): The IP address to look up.

    Returns:
        str: A 2-letter country code.

    """
    if ip_addr.find(':') >= 0:
        return pygeoip.GeoIP(settings.GEOIPV6_PATH).country_code_by_addr(ip_addr)
    else:
        return pygeoip.GeoIP(settings.GEOIP_PATH).country_code_by_addr(ip_addr)


def _get_message_url_path_from_db(course_key, access_point):
    """Retrieve the "blocked" message from the database.

    Arguments:
        course_key (CourseKey): The location of the course.
        access_point (str): How the user was trying to access the course.
            Can be either "enrollment" or "courseware".

    Returns:
        unicode: The URL path to a page explaining why the user was blocked.

    """
    # Fallback in case we're not able to find a message path
    # Presumably if the caller is requesting a URL, the caller
    # has already determined that the user should be blocked.
    # We use generic messaging unless we find something more specific,
    # but *always* return a valid URL path.
    default_path = reverse(
        'embargo_blocked_message',
        kwargs={
            'access_point': 'courseware',
            'message_key': 'default'
        }
    )

    # First check whether this is a restricted course.
    # The list of restricted courses is cached, so this does
    # not require a database query.
    if not RestrictedCourse.is_restricted_course(course_key):
        return default_path

    # Retrieve the message key from the restricted course
    # for this access point, then determine the URL.
    try:
        course = RestrictedCourse.objects.get(course_key=course_key)
        msg_key = course.message_key_for_access_point(access_point)
        return reverse(
            'embargo_blocked_message',
            kwargs={
                'access_point': access_point,
                'message_key': msg_key
            }
        )
    except RestrictedCourse.DoesNotExist:
        return default_path
