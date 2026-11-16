import unittest

from positive_control import matching_drops


class DropControlTests(unittest.TestCase):
    def test_requires_native_drop_exact_path_destination_and_bound_port(self):
        attempt = dict(kind='client_attempt', local_port=1234, remote_ip='192.0.2.1', remote_port=443, protocol=6, attempt_qpc=100)
        event = dict(attempt, kind='wfp_other', event_type_name='classify_drop',
                     app_path='\\device\\lab\\app-b.exe', recv_qpc=101)
        self.assertEqual([event], matching_drops([event], '\\device\\lab\\app-b.exe', attempt))
        for change in [dict(kind='wfp'), dict(event_type_name='classify_allow'),
                       dict(app_path='\\device\\elsewhere\\app-b.exe'), dict(remote_ip='192.0.2.2'),
                       dict(local_port=5678), dict(protocol=17), dict(recv_qpc=99)]:
            self.assertEqual([], matching_drops([dict(event, **change)], '\\device\\lab\\app-b.exe', attempt))


if __name__ == '__main__':
    unittest.main()
