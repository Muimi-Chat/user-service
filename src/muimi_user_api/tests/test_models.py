from django.test import TestCase
from django.utils import timezone
from userapi.models import Account, EmailHistoryLog, SessionToken, ServiceLog, CommonPasswords
from userapi.enums.log_severity import LogSeverity
from userapi.enums.account_status import AccountStatus
import uuid


class ModelTestCase(TestCase):
    def setUp(self):
        self.account = Account.objects.create(
            username="testuser",
            hashed_password="hashedpassword123",
            encrypted_email="encryptedemail123",
            hashed_email="hashedemail123"
        )

        self.email_history_log = EmailHistoryLog.objects.create(
            account=self.account,
            encrypted_email="oldencryptedemail123"
        )

        self.session_token = SessionToken.objects.create(
            account=self.account,
            hashed_token="hashedtoken123",
            encrypted_client_info="encryptedclientinfo",
            encrypted_country="encryptedcountry",
            expiry_date=timezone.now() + timezone.timedelta(days=1)
        )

        self.service_log = ServiceLog.objects.create(
            content="This is a log message",
            severity=LogSeverity.LOG
        )

        self.common_password = CommonPasswords.objects.create(
            password="commonpassword123"
        )

    def test_account_creation(self):
        self.assertEqual(self.account.username, "testuser")
        self.assertEqual(self.account.hashed_password, "hashedpassword123")
        self.assertEqual(self.account.encrypted_email, "encryptedemail123")
        self.assertEqual(self.account.hashed_email, "hashedemail123")
        self.assertFalse(self.account.deleted)
        self.assertIsNone(self.account.deleted_at)
        self.assertTrue(self.account.created_at)
        self.assertEqual(self.account.status, AccountStatus.OK)
        self.assertFalse(self.account.authenticated)
        self.assertFalse(self.account.totp_enabled)

    def test_email_history_log_creation(self):
        self.assertEqual(self.email_history_log.account, self.account)
        self.assertEqual(self.email_history_log.encrypted_email, "oldencryptedemail123")
        self.assertTrue(self.email_history_log.created_at)

    def test_session_token_creation(self):
        self.assertEqual(self.session_token.account, self.account)
        self.assertEqual(self.session_token.hashed_token, "hashedtoken123")
        self.assertEqual(self.session_token.encrypted_client_info, "encryptedclientinfo")
        self.assertEqual(self.session_token.encrypted_country, "encryptedcountry")
        self.assertTrue(self.session_token.expiry_date)
        self.assertTrue(self.session_token.creation_date)

    def test_service_log_creation(self):
        self.assertEqual(self.service_log.content, "This is a log message")
        self.assertEqual(self.service_log.severity, LogSeverity.LOG)
        self.assertTrue(self.service_log.created_at)

    def test_common_passwords_creation(self):
        self.assertEqual(self.common_password.password, "commonpassword123")
