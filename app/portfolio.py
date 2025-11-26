import pandas as pd
import chromadb
import uuid
from s3_manager import S3Manager
from resume_parser import ResumeParser


class Portfolio:
    def __init__(self, file_path="app/resource/my_portfolio.csv", username=None, llm=None):
        self.file_path = file_path
        self.username = username
        self.llm = llm
        self.s3_manager = S3Manager() if username else None
        self.resume_parser = ResumeParser(llm) if llm else None
        
        # Try to read CSV data as fallback
        try:
            self.data = pd.read_csv(file_path)
        except:
            self.data = None
        
        self.chroma_client = chromadb.PersistentClient('vectorstore')
        # Use user-specific collection if username provided
        # Sanitize username for ChromaDB collection name (alphanumeric, underscore, hyphen only)
        if username:
            sanitized_username = ''.join(c if c.isalnum() or c in ['_', '-'] else '_' for c in username)
            collection_name = f"portfolio_{sanitized_username}"
        else:
            collection_name = "portfolio"
        self.collection = self.chroma_client.get_or_create_collection(name=collection_name)

    def load_portfolio(self):
        """Load portfolio data - prioritize resume over CSV"""
        
        # First, try to load from user's resume
        if self.username and self.s3_manager and self.s3_manager.is_configured:
            resume_loaded = self._load_from_resume()
            if resume_loaded:
                return
        
        # Fallback to CSV if resume not available
        if self.data is not None:
            self._load_from_csv()
        else:
            # If no data available at all, create empty collection
            print("Warning: No portfolio data available (neither resume nor CSV)")
    
    def _load_from_resume(self):
        """Load portfolio data from user's resume in S3"""
        try:
            # Check if user has a resume
            if not self.s3_manager.check_user_has_resume(self.username):
                return False
            
            # Download resume from S3
            result = self.s3_manager.download_resume(self.username)
            if not result['success']:
                return False
            
            # Parse resume
            file_content = result['content']
            file_name = result['filename']
            file_type = file_name.split('.')[-1] if '.' in file_name else 'pdf'
            
            resume_data = self.resume_parser.parse_resume(file_content, file_type)
            
            # Clear existing collection for this user
            if self.collection.count() > 0:
                # Delete and recreate collection with sanitized username
                sanitized_username = ''.join(c if c.isalnum() or c in ['_', '-'] else '_' for c in self.username)
                collection_name = f"portfolio_{sanitized_username}"
                self.chroma_client.delete_collection(name=collection_name)
                self.collection = self.chroma_client.get_or_create_collection(name=collection_name)
            
            # Add skills to vector database
            skills = resume_data.get('skills', [])
            if skills:
                for skill in skills:
                    self.collection.add(
                        documents=skill,
                        metadatas={"source": "resume", "skill": skill},
                        ids=[str(uuid.uuid4())]
                    )
            
            # Add experience as additional context
            experiences = resume_data.get('experience', [])
            for exp in experiences:
                if isinstance(exp, dict):
                    exp_text = f"{exp.get('role', '')} at {exp.get('company', '')}"
                else:
                    exp_text = str(exp)
                
                self.collection.add(
                    documents=exp_text,
                    metadatas={"source": "resume", "type": "experience"},
                    ids=[str(uuid.uuid4())]
                )
            
            # Add projects
            projects = resume_data.get('projects', [])
            for project in projects:
                if isinstance(project, dict):
                    proj_text = project.get('description', str(project))
                else:
                    proj_text = str(project)
                
                self.collection.add(
                    documents=proj_text,
                    metadatas={"source": "resume", "type": "project"},
                    ids=[str(uuid.uuid4())]
                )
            
            return True
        except Exception as e:
            print(f"Error loading resume: {e}")
            return False
    
    def _load_from_csv(self):
        """Load portfolio data from CSV file (fallback method)"""
        if not self.collection.count():
            for _, row in self.data.iterrows():
                self.collection.add(
                    documents=row["Techstack"],
                    metadatas={"links": row["Links"]},
                    ids=[str(uuid.uuid4())]
                )

    def query_links(self, skills):
        """Query portfolio for matching skills and return relevant information"""
        results = self.collection.query(query_texts=skills, n_results=2)
        
        # Format results based on source
        metadata_list = results.get('metadatas', [])
        documents = results.get('documents', [])
        
        formatted_results = []
        for i, metadata_group in enumerate(metadata_list):
            for metadata in metadata_group:
                if 'links' in metadata:
                    # CSV-based portfolio
                    formatted_results.append(metadata)
                elif 'source' in metadata and metadata['source'] == 'resume':
                    # Resume-based portfolio
                    doc_text = documents[i] if i < len(documents) else []
                    formatted_results.append({
                        'skill': metadata.get('skill', ''),
                        'type': metadata.get('type', 'skill'),
                        'description': doc_text
                    })
        
        return formatted_results
    
    def get_resume_summary(self):
        """Get summary of user's resume data"""
        if not self.username or not self.s3_manager:
            return None
        
        try:
            if not self.s3_manager.check_user_has_resume(self.username):
                return None
            
            result = self.s3_manager.download_resume(self.username)
            if not result['success']:
                return None
            
            file_content = result['content']
            file_name = result['filename']
            file_type = file_name.split('.')[-1] if '.' in file_name else 'pdf'
            
            resume_data = self.resume_parser.parse_resume(file_content, file_type)
            return resume_data
        except Exception as e:
            print(f"Error getting resume summary: {e}")
            return None
