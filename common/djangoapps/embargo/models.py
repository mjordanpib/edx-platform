"""
Models for embargoing visits to certain courses by IP address.

WE'RE USING MIGRATIONS!

If you make changes to this model, be sure to create an appropriate migration
file and check it in at the same time as your model changes. To do that,

1. Go to the edx-platform dir
2. ./manage.py lms schemamigration embargo --auto description_of_your_change
3. Add the migration file created in edx-platform/common/djangoapps/embargo/migrations/
"""

import ipaddr
import json

from django.db import models
from django.utils.translation import ugettext as _, ugettext_lazy
from django.core.cache import cache
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

from django_countries.fields import CountryField
from django_countries import countries

from config_models.models import ConfigurationModel
from xmodule_django.models import CourseKeyField, NoneToEmptyManager

from embargo.messages import ENROLL_MESSAGES, COURSEWARE_MESSAGES


class EmbargoedCourse(models.Model):
    """
    Enable course embargo on a course-by-course basis.
    """
    objects = NoneToEmptyManager()

    # The course to embargo
    course_id = CourseKeyField(max_length=255, db_index=True, unique=True)

    # Whether or not to embargo
    embargoed = models.BooleanField(default=False)

    @classmethod
    def is_embargoed(cls, course_id):
        """
        Returns whether or not the given course id is embargoed.

        If course has not been explicitly embargoed, returns False.
        """
        try:
            record = cls.objects.get(course_id=course_id)
            return record.embargoed
        except cls.DoesNotExist:
            return False

    def __unicode__(self):
        not_em = "Not "
        if self.embargoed:
            not_em = ""
        # pylint: disable=no-member
        return u"Course '{}' is {}Embargoed".format(self.course_id.to_deprecated_string(), not_em)


class EmbargoedState(ConfigurationModel):
    """
    Register countries to be embargoed.
    """
    # The countries to embargo
    embargoed_countries = models.TextField(
        blank=True,
        help_text="A comma-separated list of country codes that fall under U.S. embargo restrictions"
    )

    @property
    def embargoed_countries_list(self):
        """
        Return a list of upper case country codes
        """
        if self.embargoed_countries == '':
            return []
        return [country.strip().upper() for country in self.embargoed_countries.split(',')]  # pylint: disable=no-member


class RestrictedCourse(models.Model):
    """Course with access restrictions.

    Restricted courses can block users at two points:

    1) When enrolling in a course.
    2) When attempting to access a course the user is already enrolled in.

    The second case can occur when new restrictions
    are put into place; for example, when new countries
    are embargoed.

    Restricted courses can be configured to display
    messages to users when they are blocked.
    These displayed on pages served by the embargo app.

    """
    CACHE_KEY = 'embargo.restricted_courses'

    ENROLL_MSG_KEY_CHOICES = tuple([
        (msg_key, msg.description)
        for msg_key, msg in ENROLL_MESSAGES.iteritems()
    ])

    COURSEWARE_MSG_KEY_CHOICES = tuple([
        (msg_key, msg.description)
        for msg_key, msg in COURSEWARE_MESSAGES.iteritems()
    ])

    course_key = CourseKeyField(
        max_length=255, db_index=True, unique=True,
        help_text=ugettext_lazy(u"The course key for the restricted course.")
    )

    enroll_msg_key = models.CharField(
        max_length=255,
        choices=ENROLL_MSG_KEY_CHOICES,
        default='default',
        help_text=ugettext_lazy(u"The message to show when a user is blocked from enrollment.")
    )

    access_msg_key = models.CharField(
        max_length=255,
        choices=COURSEWARE_MSG_KEY_CHOICES,
        default='default',
        help_text=ugettext_lazy(u"The message to show when a user is blocked from accessing a course.")
    )

    @classmethod
    def is_restricted_course(cls, course_id):
        """
        Check if the course is in restricted list

        Args:
            course_id (str): course_id to look for

        Returns:
            Boolean
            True if course is in restricted course list.
        """
        return unicode(course_id) in cls._get_restricted_courses_from_cache()

    @classmethod
    def _get_restricted_courses_from_cache(cls):
        """
        Cache all restricted courses and returns the list of course_keys that are restricted
        """
        restricted_courses = cache.get(cls.CACHE_KEY)
        if not restricted_courses:
            restricted_courses = list(RestrictedCourse.objects.values_list('course_key', flat=True))
            cache.set(cls.CACHE_KEY, restricted_courses)
        return restricted_courses

    def summarize_rules(self):
        """Return a summary of all access rules for this course.

        This is useful for recording an audit trail of rule changes.
        The returned dictionary is JSON-serializable.

        Returns:
            dict

        Example Usage:
        >>> restricted_course.summarize_rules()
        {
            'enroll_msg': 'default',
            'access_msg': 'default',
            'country_rules': [
                {'country': 'IR', 'rule_type': 'blacklist'},
                {'country': 'CU', 'rule_type': 'blacklist'}
            ]
        }

        """
        country_rules_for_course = (
            CountryAccessRule.objects
        ).select_related('restricted_country').filter(restricted_course=self)

        return {
            'enroll_msg': self.enroll_msg_key,
            'access_msg': self.access_msg_key,
            'country_rules': [
                {
                    'country': unicode(rule.country.country),
                    'rule_type': rule.rule_type
                }
                for rule in country_rules_for_course
            ]
        }

    def message_key_for_access_point(self, access_point):
        """Determine which message to show the user.

        The message can be configured per-course and depends
        on how the user is trying to access the course
        (trying to enroll or accessing courseware).

        Arguments:
            access_point (str): Either "courseware" or "enrollment"

        Returns:
            str: The message key.  If the access point is not valid,
                returns None instead.

        """
        if access_point == 'enrollment':
            return self.enroll_msg_key
        elif access_point == 'courseware':
            return self.access_msg_key

    def __unicode__(self):
        return unicode(self.course_key)

    def save(self, *args, **kwargs):
        """
        Clear the cached value when saving a RestrictedCourse entry
        """
        super(RestrictedCourse, self).save(*args, **kwargs)
        cache.delete(self.CACHE_KEY)

    def delete(self, using=None):
        super(RestrictedCourse, self).delete()
        cache.delete(self.CACHE_KEY)


class Country(models.Model):
    """Representation of a country.

    This is used to define country-based access rules.
    There is a data migration that creates entries for
    each country code.

    """
    country = CountryField(
        db_index=True, unique=True,
        help_text=ugettext_lazy(u"Two character ISO country code.")
    )

    def __unicode__(self):
        return u"{name} ({code})".format(
            name=unicode(self.country.name),
            code=unicode(self.country)
        )

    class Meta:
        """Default ordering is ascending by country code """
        ordering = ['country']


class CountryAccessRule(models.Model):
    """Course access rule based on the user's country.

    The rule applies to a particular course-country pair.
    Countries can either be whitelisted or blacklisted,
    but not both.

    To determine whether a user has access to a course
    based on the user's country:

    1) Retrieve the list of whitelisted countries for the course.
    (If there aren't any, then include every possible country.)

    2) From the initial list, remove all blacklisted countries
    for the course.

    """

    WHITELIST_RULE = 'whitelist'
    BLACKLIST_RULE = 'blacklist'

    RULE_TYPE_CHOICES = (
        (WHITELIST_RULE, 'Whitelist (allow only these countries)'),
        (BLACKLIST_RULE, 'Blacklist (block these countries)'),
    )

    rule_type = models.CharField(
        max_length=255,
        choices=RULE_TYPE_CHOICES,
        default=BLACKLIST_RULE,
        help_text=ugettext_lazy(
            u"Whether to include or exclude the given course. "
            u"If whitelist countries are specified, then ONLY users from whitelisted countries "
            u"will be able to access the course.  If blacklist countries are specified, then "
            u"users from blacklisted countries will NOT be able to access the course."
        )
    )

    restricted_course = models.ForeignKey(
        "RestrictedCourse",
        help_text=ugettext_lazy(u"The course to which this rule applies.")
    )

    country = models.ForeignKey(
        "Country",
        help_text=ugettext_lazy(u"The country to which this rule applies.")
    )

    CACHE_KEY = u"embargo.allowed_countries.{course_key}"

    @classmethod
    def check_country_access(cls, course_id, country):
        """
        Check if the country is either in whitelist or blacklist of countries for the course_id

        Args:
            course_id (str): course_id to look for
            country (str): A 2 characters code of country

        Returns:
            Boolean
            True if country found in allowed country
            otherwise check given country exists in list
        """
        cache_key = cls.CACHE_KEY.format(course_key=course_id)
        allowed_countries = cache.get(cache_key)
        if not allowed_countries:
            allowed_countries = cls._get_country_access_list(course_id)
            cache.set(cache_key, allowed_countries)

        return country == '' or country in allowed_countries

    @classmethod
    def _get_country_access_list(cls, course_id):
        """
        if a course is blacklist for two countries then course can be accessible from
        any where except these two countries.
        if a course is whitelist for two countries then course can be accessible from
        these countries only.
        Args:
            course_id (str): course_id to look for
        Returns:
            List
            Consolidated list of accessible countries for given course
        """

        whitelist_countries = set()
        blacklist_countries = set()

        # Retrieve all rules in one database query, performing the "join" with the Country table
        rules_for_course = CountryAccessRule.objects.select_related('country').filter(
            restricted_course__course_key=course_id
        )

        # Filter the rules into a whitelist and blacklist in one pass
        for rule in rules_for_course:
            if rule.rule_type == 'whitelist':
                whitelist_countries.add(rule.country.country.code)
            elif rule.rule_type == 'blacklist':
                blacklist_countries.add(rule.country.country.code)

        # If there are no whitelist countries, default to all countries
        if not whitelist_countries:
            whitelist_countries = set(code[0] for code in list(countries))

        # Consolidate the rules into a single list of countries
        # that have access to the course.
        return list(whitelist_countries - blacklist_countries)

    def __unicode__(self):
        if self.rule_type == self.WHITELIST_RULE:
            return _(u"Whitelist {country} for {course}").format(
                course=unicode(self.restricted_course.course_key),
                country=unicode(self.country),
            )
        elif self.rule_type == self.BLACKLIST_RULE:
            return _(u"Blacklist {country} for {course}").format(
                course=unicode(self.restricted_course.course_key),
                country=unicode(self.country),
            )

    def save(self, *args, **kwargs):
        """Clear the cached value when saving an entry. """
        super(CountryAccessRule, self).save(*args, **kwargs)
        self._invalidate_cache()

    def delete(self, using=None):
        """Clear the cached value when deleting an entry. """
        super(CountryAccessRule, self).delete()
        self._invalidate_cache()

    def _invalidate_cache(self):
        cache_key = self.CACHE_KEY.format(course_key=self.restricted_course.course_key)
        cache.delete(cache_key)

    class Meta:
        """a course can be added with either black or white list.  """
        unique_together = (
            # This restriction ensures that a country is on
            # either the whitelist or the blacklist, but
            # not both (for a particular course).
            ("restricted_course", "country")
        )


class CourseAccessRuleHistory(models.Model):
    """History of course access rule changes. """

    timestamp = models.DateTimeField(db_index=True, auto_now_add=True)
    course_key = CourseKeyField(max_length=255, db_index=True)
    rules = models.TextField(null=True, blank=True)

    DELETED_PLACEHOLDER = "DELETED"

    @receiver(post_save, sender=RestrictedCourse)
    def restricted_course_post_save(sender, instance, **kwargs):
        """Save a history entry when the restricted course changes. """
        CourseAccessRuleHistory.save_rule_summary(instance)

    @receiver(post_delete, sender=RestrictedCourse)
    def restricted_course_post_delete(sender, instance, **kwargs):
        """Save a history entry when a restricted course is deleted. """

        # At the point this is called, the access rules may not have
        # been deleted yet.  When the rules *are* deleted, the
        # restricted course entry may no longer exist, so we
        # won't be able to summarize the rules for the course.
        # To handle this, we save a placeholder "DELETED" entry
        # so that it's clear in the audit that the restricted
        # course (along with all its rules) was deleted.
        CourseAccessRuleHistory.objects.create(
            course_key=instance.course_key,
            rules=CourseAccessRuleHistory.DELETED_PLACEHOLDER
        )

    @receiver(post_save, sender=CountryAccessRule)
    def country_access_post_save(sender, instance, **kwargs):
        """Save a history entry when a country access rule changes. """
        CourseAccessRuleHistory.save_rule_summary(instance.restricted_course)

    @receiver(post_delete, sender=CountryAccessRule)
    def country_access_post_delete(sender, instance, **kwargs):
        """Save a history entry when a country access rule is deleted. """
        try:
            restricted_course = instance.restricted_course
        except RestrictedCourse.DoesNotExist:
            # When Django admin deletes a restricted course, it will
            # also delete the rules associated with that course.
            # At this point, we can't access the restricted course
            # from the rule beause it may already have been deleted.
            # If this happens, we don't need to record anything,
            # since we already record a placeholder "DELETED"
            # entry when the restricted course record is deleted.
            pass
        else:
            CourseAccessRuleHistory.save_rule_summary(restricted_course)

    @staticmethod
    def save_rule_summary(restricted_course):
        """Save a summary of the rules for a course to the database.

        Arguments:
            restricted_course (RestrictedCourse)

        Returns:
            None

        """
        rules_summary = restricted_course.summarize_rules()
        rules_json = json.dumps(rules_summary)
        CourseAccessRuleHistory.objects.create(
            course_key=restricted_course.course_key,
            rules=rules_json
        )


class IPFilter(ConfigurationModel):
    """
    Register specific IP addresses to explicitly block or unblock.
    """
    whitelist = models.TextField(
        blank=True,
        help_text="A comma-separated list of IP addresses that should not fall under embargo restrictions."
    )

    blacklist = models.TextField(
        blank=True,
        help_text="A comma-separated list of IP addresses that should fall under embargo restrictions."
    )

    class IPFilterList(object):
        """
        Represent a list of IP addresses with support of networks.
        """

        def __init__(self, ips):
            self.networks = [ipaddr.IPNetwork(ip) for ip in ips]

        def __iter__(self):
            for network in self.networks:
                yield network

        def __contains__(self, ip):
            try:
                ip = ipaddr.IPAddress(ip)
            except ValueError:
                return False

            for network in self.networks:
                if network.Contains(ip):
                    return True

            return False

    @property
    def whitelist_ips(self):
        """
        Return a list of valid IP addresses to whitelist
        """
        if self.whitelist == '':
            return []
        return self.IPFilterList([addr.strip() for addr in self.whitelist.split(',')])  # pylint: disable=no-member

    @property
    def blacklist_ips(self):
        """
        Return a list of valid IP addresses to blacklist
        """
        if self.blacklist == '':
            return []
        return self.IPFilterList([addr.strip() for addr in self.blacklist.split(',')])  # pylint: disable=no-member
