#!/usr/bin/env python
import datetime
from public import public

# https://docs.python.org/3/library/datetime.html#timedelta-objects


@public
class Total:
    total_seconds = None

    def __init__(self, total_seconds):
        self.total_seconds = total_seconds

    @property
    def seconds(self):
        return int(self.total_seconds)

    @property
    def minutes(self):
        return int(self.seconds / 60)

    @property
    def hours(self):
        return int(self.minutes / 60)

    @property
    def days(self):
        return int(self.hours / 24)

    @property
    def weeks(self):
        return int(self.days / 7)

    @property
    def months(self):
        return int(self.days / 30)

    @property
    def years(self):
        return int(self.days / 365)


@public
class Timedelta(datetime.timedelta):
    def __new__(self, *args, **kwargs):
        if args:
            kwargs["seconds"] = args[0].total_seconds()
            kwargs["microseconds"] = args[0].microseconds
        return datetime.timedelta.__new__(self, **kwargs)

    @property
    def total(self):
        return Total(self.total_seconds())
