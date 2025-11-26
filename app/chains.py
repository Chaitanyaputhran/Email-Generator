import os
import re
from langchain_groq import ChatGroq
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.exceptions import OutputParserException
from dotenv import load_dotenv

load_dotenv()

class Chain:
    def __init__(self):
        self.llm = ChatGroq(temperature=0, groq_api_key=os.getenv("GROQ_API_KEY"), model_name="llama-3.3-70b-versatile")

    def extract_jobs(self, cleaned_text):
        prompt_extract = PromptTemplate.from_template(
            """
            ### SCRAPED TEXT FROM WEBSITE:
            {page_data}
            ### INSTRUCTION:
            The scraped text is from the career's page of a website.
            Your job is to extract the job postings and return them in JSON format containing the following keys: `role`, `experience`, `skills` and `description`.
            Only return the valid JSON.
            ### VALID JSON (NO PREAMBLE):
            """
        )
        chain_extract = prompt_extract | self.llm
        res = chain_extract.invoke(input={"page_data": cleaned_text})
        try:
            json_parser = JsonOutputParser()
            res = json_parser.parse(res.content)
        except OutputParserException:
            raise OutputParserException("Context too big. Unable to parse jobs.")
        return res if isinstance(res, list) else [res]

    def extract_emails(self, cleaned_text):
        """
        Extract email addresses from scraped text using both regex and LLM.
        Returns a list of unique email addresses.
        """
        # First try regex extraction (faster and more reliable for standard emails)
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        regex_emails = re.findall(email_pattern, cleaned_text)
        
        # Also use LLM for context-aware extraction
        prompt_extract = PromptTemplate.from_template(
            """
            ### SCRAPED TEXT FROM WEBSITE:
            {page_data}
            ### INSTRUCTION:
            Extract all email addresses from the scraped text.
            Return them in JSON format as a list with the key `emails`.
            Only return the valid JSON.
            ### VALID JSON (NO PREAMBLE):
            """
        )
        chain_extract = prompt_extract | self.llm
        res = chain_extract.invoke(input={"page_data": cleaned_text})
        
        try:
            json_parser = JsonOutputParser()
            parsed_res = json_parser.parse(res.content)
            llm_emails = parsed_res.get("emails", [])
        except OutputParserException:
            llm_emails = []
        
        # Combine and deduplicate emails from both methods
        all_emails = list(set(regex_emails + llm_emails))
        return all_emails

    def write_mail(self, job, links, user_info=None):
        """
        Write personalized cold email based on job and user's resume/portfolio
        
        Args:
            job: Job description dictionary
            links: Portfolio links or resume-based skills
            user_info: Optional user resume summary for personalization
        """
        # Check if links are from resume (dict format) or CSV (simple format)
        portfolio_text = self._format_portfolio_info(links, user_info)
        
        prompt_email = PromptTemplate.from_template(
            """
            ### JOB DESCRIPTION:
            {job_description}

            ### CANDIDATE PROFILE:
            {portfolio_info}

            ### INSTRUCTION:
            You are writing a cold email on behalf of a job applicant to the hiring manager for the position described above.
            
            The email should:
            1. Express genuine interest in the specific role
            2. Highlight relevant skills and experiences that match the job requirements
            3. Mention specific achievements or projects that demonstrate capability
            4. Be concise, professional, and personalized
            5. Include a clear call-to-action
            
            Use the candidate's profile information to make the email authentic and relevant.
            Do not provide a preamble or subject line.
            
            ### EMAIL (NO PREAMBLE):

            """
        )
        chain_email = prompt_email | self.llm
        res = chain_email.invoke({
            "job_description": str(job), 
            "portfolio_info": portfolio_text
        })
        return res.content
    
    def _format_portfolio_info(self, links, user_info=None):
        """Format portfolio information for email generation"""
        if not links:
            return "No specific portfolio information available."
        
        formatted = []
        
        # Check if links contain resume-based data
        for item in links:
            if isinstance(item, dict):
                if 'skill' in item:
                    formatted.append(f"- Skill: {item['skill']}")
                elif 'type' in item:
                    formatted.append(f"- {item['type'].title()}: {item.get('description', '')}")
                elif 'links' in item:
                    formatted.append(f"- Portfolio Link: {item['links']}")
        
        # Add user info summary if available
        if user_info:
            if 'summary' in user_info:
                formatted.insert(0, f"Professional Summary: {user_info['summary']}")
            if 'skills' in user_info and user_info['skills']:
                formatted.insert(1, f"Key Skills: {', '.join(user_info['skills'][:10])}")
        
        return "\n".join(formatted) if formatted else "Candidate has relevant technical experience."

if __name__ == "__main__":
    print(os.getenv("GROQ_API_KEY"))
    
    # Example usage
    chain = Chain()
    sample_text = """
    Contact us at jobs@atliq.com or support@atliq.com
    For more information, reach out to hr.team@company.org
    """
    emails = chain.extract_emails(sample_text)
    print("Extracted emails:", emails)
