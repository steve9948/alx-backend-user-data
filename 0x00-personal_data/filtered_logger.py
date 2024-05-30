#!/usr/bin/env python3
"""
This script connects to a MySQL database,
retrieves user data, and logs the data
with sensitive information redacted.
"""

from typing import List
import re
import logging
import os
import mysql.connector


PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


def filter_datum(
        fields: List[str], redaction: str, message: str, separator: str
        ) -> str:
    """
    Obfuscates specified fields in a log message.

    Args:
        fields (List[str]): List of strings representing fields to obfuscate.
        redaction (str): String to replace the field values with.
        message (str): The log message containing fields to obfuscate.
        separator (str): The character separating the fields in the
        log message.

    Returns:
        str: The obfuscated log message.
    """
    for field in fields:
        message = re.sub(
                f"{field}=.*?{separator}", f"{field}={redaction}{separator}",
                message)
    return message


class RedactingFormatter(logging.Formatter):
    """
    Redacting Formatter class to obfuscate PII fields in log messages.
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initialize the formatter with specified fields to redact.

        Args:
            fields (List[str]): List of fields to redact.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record, redacting sensitive fields.

        Args:
            record (logging.LogRecord): The log record to format.

        Returns:
            str: The formatted and redacted log message.
        """
        message = super(RedactingFormatter, self).format(record)
        return filter_datum(
                self.fields, self.REDACTION, message, self.SEPARATOR)


def get_logger() -> logging.Logger:
    """
    Create and configure a logger to log user data with
    sensitive fields redacted.

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.StreamHandler()
    formatter = RedactingFormatter(PII_FIELDS)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Establish a connection to the MySQL database.

    Returns:
        mysql.connector.connection.MySQLConnection:
        MySQL database connection object.
    """
    user = os.getenv('PERSONAL_DATA_DB_USERNAME', 'root')
    passwd = os.getenv('PERSONAL_DATA_DB_PASSWORD', '')
    host = os.getenv('PERSONAL_DATA_DB_HOST', 'localhost')
    db_name = os.getenv('PERSONAL_DATA_DB_NAME')

    return mysql.connector.connect(
            user=user, password=passwd, host=host, database=db_name)


def main():
    """
    Main function to retrieve user data from the
    database and log it with redaction.
    """
    db = get_db()
    logger = get_logger()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    fields = cursor.column_names

    for row in cursor:
        message = "; ".join(f"{k}={v}" for k, v in zip(fields, row))
        logger.info(message.strip())

    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
