"""
S3 Manager for Resume Storage and Retrieval
Handles uploading, downloading, and managing user resumes in AWS S3
"""

import boto3
from botocore.exceptions import ClientError
import os
from dotenv import load_dotenv
import json
from datetime import datetime

load_dotenv()


class S3Manager:
    def __init__(self):
        self.aws_region = os.getenv('AWS_REGION', 'us-east-1')
        self.bucket_name = os.getenv('S3_BUCKET_NAME')
        
        # Check if S3 is configured
        self.is_configured = self.bucket_name and self.bucket_name != 'your_bucket_name_here'
        
        # Only create S3 client if configured
        if self.is_configured:
            try:
                self.s3_client = boto3.client('s3', region_name=self.aws_region)
                # Test credentials by trying to access the specific bucket (doesn't require ListAllBuckets permission)
                try:
                    self.s3_client.head_bucket(Bucket=self.bucket_name)
                except ClientError as e:
                    # Bucket might not exist yet, but credentials are valid
                    if e.response['Error']['Code'] in ['404', 'NoSuchBucket']:
                        pass  # Bucket doesn't exist, but credentials work
                    else:
                        raise  # Other error, credentials might be invalid
            except Exception as e:
                print(f"S3 credentials not configured: {e}")
                self.is_configured = False
                self.s3_client = None
        else:
            self.s3_client = None
    
    def create_bucket_if_not_exists(self):
        """Create S3 bucket if it doesn't exist"""
        try:
            # Check if bucket exists
            self.s3_client.head_bucket(Bucket=self.bucket_name)
            return {'success': True, 'message': 'Bucket exists'}
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == '404':
                # Bucket doesn't exist, create it
                try:
                    if self.aws_region == 'us-east-1':
                        self.s3_client.create_bucket(Bucket=self.bucket_name)
                    else:
                        self.s3_client.create_bucket(
                            Bucket=self.bucket_name,
                            CreateBucketConfiguration={'LocationConstraint': self.aws_region}
                        )
                    return {'success': True, 'message': 'Bucket created successfully'}
                except ClientError as create_error:
                    return {'success': False, 'message': f'Failed to create bucket: {str(create_error)}'}
            else:
                return {'success': False, 'message': f'Error checking bucket: {str(e)}'}
    
    def upload_resume(self, username, file_content, file_name, file_type='pdf'):
        """
        Upload user resume to S3
        
        Args:
            username: User's username
            file_content: File content in bytes
            file_name: Original file name
            file_type: File type (pdf, docx, txt)
        
        Returns:
            dict: Success status and message/S3 key
        """
        if not self.is_configured or self.s3_client is None:
            return {'success': False, 'message': 'S3 is not configured. Please configure AWS credentials.'}
        
        try:
            # Create a unique S3 key for the resume
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            s3_key = f"resumes/{username}/{timestamp}_{file_name}"
            
            # Upload file to S3
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=s3_key,
                Body=file_content,
                ContentType=self._get_content_type(file_type),
                Metadata={
                    'username': username,
                    'upload_date': timestamp,
                    'original_filename': file_name
                }
            )
            
            # Update user metadata with resume location
            self._update_user_resume_metadata(username, s3_key, file_name)
            
            return {
                'success': True,
                'message': 'Resume uploaded successfully',
                's3_key': s3_key
            }
        except ClientError as e:
            return {'success': False, 'message': f'Failed to upload resume: {str(e)}'}
    
    def download_resume(self, username):
        """
        Download user's latest resume from S3
        
        Args:
            username: User's username
        
        Returns:
            dict: Success status and file content/message
        """
        try:
            # Get user's resume metadata
            metadata = self._get_user_resume_metadata(username)
            
            if not metadata or 's3_key' not in metadata:
                return {'success': False, 'message': 'No resume found for user'}
            
            s3_key = metadata['s3_key']
            
            # Download file from S3
            response = self.s3_client.get_object(
                Bucket=self.bucket_name,
                Key=s3_key
            )
            
            file_content = response['Body'].read()
            
            return {
                'success': True,
                'content': file_content,
                'filename': metadata.get('filename', 'resume.pdf'),
                's3_key': s3_key
            }
        except ClientError as e:
            return {'success': False, 'message': f'Failed to download resume: {str(e)}'}
    
    def check_user_has_resume(self, username):
        """
        Check if user has uploaded a resume
        
        Args:
            username: User's username
        
        Returns:
            bool: True if user has resume, False otherwise
        """
        metadata = self._get_user_resume_metadata(username)
        return metadata is not None and 's3_key' in metadata
    
    def delete_resume(self, username):
        """
        Delete user's resume from S3
        
        Args:
            username: User's username
        
        Returns:
            dict: Success status and message
        """
        try:
            # Get user's resume metadata
            metadata = self._get_user_resume_metadata(username)
            
            if not metadata or 's3_key' not in metadata:
                return {'success': False, 'message': 'No resume found for user'}
            
            s3_key = metadata['s3_key']
            
            # Delete file from S3
            self.s3_client.delete_object(
                Bucket=self.bucket_name,
                Key=s3_key
            )
            
            # Delete metadata
            self._delete_user_resume_metadata(username)
            
            return {'success': True, 'message': 'Resume deleted successfully'}
        except ClientError as e:
            return {'success': False, 'message': f'Failed to delete resume: {str(e)}'}
    
    def _get_content_type(self, file_type):
        """Get content type for file upload"""
        content_types = {
            'pdf': 'application/pdf',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'doc': 'application/msword',
            'txt': 'text/plain'
        }
        return content_types.get(file_type.lower(), 'application/octet-stream')
    
    def _update_user_resume_metadata(self, username, s3_key, filename):
        """Store user resume metadata in S3"""
        try:
            metadata_key = f"metadata/{username}/resume_metadata.json"
            metadata = {
                'username': username,
                's3_key': s3_key,
                'filename': filename,
                'upload_date': datetime.now().isoformat()
            }
            
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=metadata_key,
                Body=json.dumps(metadata),
                ContentType='application/json'
            )
        except ClientError as e:
            print(f"Failed to update metadata: {str(e)}")
    
    def _get_user_resume_metadata(self, username):
        """Retrieve user resume metadata from S3"""
        try:
            metadata_key = f"metadata/{username}/resume_metadata.json"
            response = self.s3_client.get_object(
                Bucket=self.bucket_name,
                Key=metadata_key
            )
            metadata = json.loads(response['Body'].read())
            return metadata
        except ClientError:
            return None
    
    def _delete_user_resume_metadata(self, username):
        """Delete user resume metadata from S3"""
        try:
            metadata_key = f"metadata/{username}/resume_metadata.json"
            self.s3_client.delete_object(
                Bucket=self.bucket_name,
                Key=metadata_key
            )
        except ClientError as e:
            print(f"Failed to delete metadata: {str(e)}")
    
    def list_user_resumes(self, username):
        """List all resumes for a user"""
        try:
            prefix = f"resumes/{username}/"
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=prefix
            )
            
            if 'Contents' not in response:
                return []
            
            resumes = []
            for obj in response['Contents']:
                resumes.append({
                    'key': obj['Key'],
                    'size': obj['Size'],
                    'last_modified': obj['LastModified']
                })
            
            return resumes
        except ClientError as e:
            print(f"Failed to list resumes: {str(e)}")
            return []
