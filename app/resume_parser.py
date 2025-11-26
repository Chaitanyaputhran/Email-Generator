"""
Resume Parser for extracting skills and experience from resumes
Handles PDF, DOCX, and TXT files
"""

import io
from typing import Dict, List
import re


class ResumeParser:
    def __init__(self, llm):
        """
        Initialize resume parser with LLM for intelligent extraction
        
        Args:
            llm: LangChain LLM instance for text analysis
        """
        self.llm = llm
    
    def parse_resume(self, file_content: bytes, file_type: str) -> Dict:
        """
        Parse resume and extract key information
        
        Args:
            file_content: Resume file content in bytes
            file_type: File extension (pdf, docx, txt)
        
        Returns:
            dict: Parsed resume data with skills, experience, etc.
        """
        # Extract text from file based on type
        text = self._extract_text(file_content, file_type)
        
        # Use LLM to extract structured information
        resume_data = self._extract_resume_data(text)
        
        return resume_data
    
    def _extract_text(self, file_content: bytes, file_type: str) -> str:
        """Extract text from different file formats"""
        file_type = file_type.lower().replace('.', '')
        
        if file_type == 'txt':
            return file_content.decode('utf-8', errors='ignore')
        
        elif file_type == 'pdf':
            try:
                from pypdf import PdfReader
                pdf_file = io.BytesIO(file_content)
                reader = PdfReader(pdf_file)
                text = ""
                for page in reader.pages:
                    text += page.extract_text() + "\n"
                return text
            except Exception as e:
                print(f"Error extracting PDF text: {e}")
                return ""
        
        elif file_type in ['docx', 'doc']:
            try:
                from docx import Document
                doc_file = io.BytesIO(file_content)
                doc = Document(doc_file)
                text = "\n".join([paragraph.text for paragraph in doc.paragraphs])
                return text
            except Exception as e:
                print(f"Error extracting DOCX text: {e}")
                return ""
        
        return ""
    
    def _extract_resume_data(self, text: str) -> Dict:
        """Use LLM to extract structured data from resume text"""
        from langchain_core.prompts import PromptTemplate
        from langchain_core.output_parsers import JsonOutputParser
        from langchain_core.exceptions import OutputParserException
        
        prompt = PromptTemplate.from_template(
            """
            ### RESUME TEXT:
            {resume_text}
            
            ### INSTRUCTION:
            Extract the following information from the resume and return it in JSON format:
            - skills: List of technical skills, programming languages, frameworks, tools
            - experience: List of work experiences with company, role, and duration
            - education: Educational qualifications
            - projects: Notable projects or achievements
            - summary: Brief professional summary (2-3 sentences)
            
            Only return valid JSON with these keys.
            ### VALID JSON (NO PREAMBLE):
            """
        )
        
        chain = prompt | self.llm
        
        try:
            response = chain.invoke({"resume_text": text[:4000]})  # Limit text length
            json_parser = JsonOutputParser()
            parsed_data = json_parser.parse(response.content)
            return parsed_data
        except OutputParserException:
            # Fallback to basic extraction
            return self._basic_extraction(text)
    
    def _basic_extraction(self, text: str) -> Dict:
        """Fallback method for basic information extraction"""
        # Common skill keywords
        skill_patterns = [
            r'\b(Python|Java|JavaScript|TypeScript|C\+\+|C#|Ruby|Go|Rust|Swift|Kotlin)\b',
            r'\b(React|Angular|Vue|Node\.js|Django|Flask|Spring|Express)\b',
            r'\b(AWS|Azure|GCP|Docker|Kubernetes|Jenkins|Git|CI/CD)\b',
            r'\b(SQL|MongoDB|PostgreSQL|MySQL|Redis|Elasticsearch)\b',
            r'\b(Machine Learning|AI|Data Science|Deep Learning|NLP|Computer Vision)\b'
        ]
        
        skills = []
        for pattern in skill_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            skills.extend(matches)
        
        # Remove duplicates and clean
        skills = list(set([skill.strip() for skill in skills]))
        
        return {
            'skills': skills,
            'experience': [],
            'education': [],
            'projects': [],
            'summary': 'Resume uploaded successfully. Skills extracted for matching.'
        }
    
    def extract_skills_only(self, resume_data: Dict) -> List[str]:
        """Extract just the skills list from parsed resume data"""
        return resume_data.get('skills', [])
