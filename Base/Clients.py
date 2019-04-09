import os
import threading
import time
from itertools import chain
from weakref import WeakKeyDictionary

from Utils import print_status, NonStringIterable

GLOBAL_OPTS = {}


class Option(object):
    def __init__(self, default, description="", validators=()):
        self.label = None
        if isinstance(validators, NonStringIterable):
            self.validators = validators
        else:
            self.validators = ()

        self.default = default
        self.description = description
        self.data = WeakKeyDictionary()

    def __get__(self, instance, owner):
        try:
            return self.data[instance]
        except KeyError:
            pass

        try:
            return self._apply_widgets(GLOBAL_OPTS[self.label])
        except KeyError:
            return self.default

    def __set__(self, instance, value):
        self.data[instance] = self._apply_widgets(value)

    def _apply_widgets(self, value):
        for validator in self.validators:
            value = validator(value)
        return value


class ClientOptionsAggregator(type):
    def __new__(mcs, name, bases, attrs):
        try:
            base_exploit_attributes = chain(map(lambda x: x.exploit_attributes, bases))
            attrs['exploit_attributes'] = {k: v for d in base_exploit_attributes for k, v in d.items()}
        except AttributeError:
            attrs['exploit_attributes'] = {}

        for key, value in attrs.items():
            if isinstance(value, Option):
                value.label = key
                attrs['exploit_attributes'].update({key: value.description})
            elif key == "__info__":
                attrs["_{}{}".format(name, key)] = value
                del attrs[key]
            elif key in attrs['exploit_attributes']:
                del attrs['exploit_attributes'][key]
        return super(ClientOptionsAggregator, mcs).__new__(mcs, name, bases, attrs)


class Client(object, metaclass=ClientOptionsAggregator):
    """ Base class for exploits. """

    target = Option(default="", description="Target IP address.")

    port = Option(default="", description="Target port.")

    @property
    def options(self):
        """ Returns list of options that user can set.

        Returns list of options aggregated by
        ExploitOptionsAggregator metaclass that user can set.

        :return: list of options that user can set
        """
        return self.exploit_attributes.keys()

    def run(self):
        raise NotImplementedError("You have to define your own 'run' method.")

    def check(self):
        raise NotImplementedError("You have to define your own 'check' method.")

    def connect(self, target, port):
        raise NotImplementedError("You have to define your own 'check' method.")

    @staticmethod
    def run_threads(threads, target, *args, **kwargs):
        workers = []
        threads_running = threading.Event()
        threads_running.set()
        for worker_id in range(int(threads)):
            worker = threading.Thread(
                target=target,
                args=chain((threads_running,), args),
                kwargs=kwargs,
                name='worker-{}'.format(worker_id),
            )
            workers.append(worker)
            worker.start()

        start = time.time()
        try:
            while worker.isAlive():
                worker.join(1)
        except KeyboardInterrupt:
            threads_running.clear()

        for worker in workers:
            worker.join()
        print_status('Elapsed time: ', time.time() - start, 'seconds')

    def __str__(self):
        return self.__module__.split('.', 2).pop().replace('.', os.sep)

