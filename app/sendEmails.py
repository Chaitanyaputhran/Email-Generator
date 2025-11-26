import boto3
from botocore.exceptions import ClientError
 
class SESEmailSender:
    def __init__(self, aws_access_key, aws_secret_key, region_name):
        self.client = boto3.client(
            "sesv2",
            region_name=region_name,
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key
        )
 
    def send_email(self, sender, recipients, subject, body_text, body_html=None):
        try:
            message = {
                "Simple": {
                    "Subject": {"Data": subject},
                    "Body": {
                        "Text": {"Data": body_text}
                    }
                }
            }
 
            # Add HTML part only if provided
            if body_html:
                message["Simple"]["Body"]["Html"] = {"Data": body_html}
 
            response = self.client.send_email(
                FromEmailAddress=sender,
                Destination={"ToAddresses": recipients},
                Content=message
            )
 
            return {
                "MessageId": response["MessageId"],
                "Status": "Success"
            }
 
        except ClientError as e:
            return {
                "Status": "Failed",
                "Error": str(e)
            }
 
 