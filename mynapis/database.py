from dotenv import load_dotenv
import os
import boto3

# Load environment variables from .env file
load_dotenv()
print("Loaded .env file")

awsSecretAccessKey = os.getenv('AWS_SECRET_ACCESS_KEY')
awsAccessKeyId = os.getenv('AWS_ACCESS_KEY_ID')
regionName = os.getenv('REGION_NAME')

print("AWS Secret Access Key:", awsSecretAccessKey)
print("AWS Access Key ID:", awsAccessKeyId)
print("Region:", regionName)

def db_connection():
    table = boto3.client('dynamodb', region_name=regionName,
                     aws_access_key_id=awsAccessKeyId, aws_secret_access_key=awsSecretAccessKey) #.Table('myn-demo')
    return table
