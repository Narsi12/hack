""" Mail notification code"""
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class MailConfig():

    """ mail configuration """
    def __init__(self, mail_user='', password='', host=''):
        self.mail_usr = mail_user
        self.mail_password = password
        self.host_name = host
        self._channel = self.__connect()

    def __connect(self):
        """ To connect the smtp server """
        if self.host_name:
            self.server = smtplib.SMTP(self.host_name)
        else:
            self.server = smtplib.SMTP('smtp.gmail.com', 587)
        self.server.ehlo()
        self.server.starttls()
        self.server.ehlo()
        self.server.login(self.mail_usr, self.mail_password)
        return self.server

    def send_mail(self, to_mail='', cc='', bcc='', subject='',
                  body='', body_type='plain'):
        """ To send the mail notification """

        msg = MIMEMultipart()
        msg['CC'] = cc
        msg['BCC'] = bcc
        msg['Subject'] = subject
        try:
            msg.attach(MIMEText(body, body_type))
            mail_list = to_mail.split(",")
            self._channel.sendmail(self.mail_usr, mail_list, msg.as_string())
            print("Mail sent Successfully")
            return "Success"
        except Exception as error:
            print("Exception: while sending the mail: ", error)

    def close_conn(self):
        """ To close the connection """
        
        self._channel.quit()
        print("Connection closed")
