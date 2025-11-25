import re

def clean_text(text):
    # Remove HTML tags
    text = re.sub(r'<[^>]*?>', '', text)
    # Remove special characters BUT preserve email-related characters
    # Preserves: @ . - _ + (all valid in email addresses)
    text = re.sub(r'[^a-zA-Z0-9 @.\-_+]', '', text)
    # Replace multiple spaces with a single space
    text = re.sub(r'\s{2,}', ' ', text)
    # Trim leading and trailing whitespace
    text = text.strip()
    # Remove extra whitespace
    text = ' '.join(text.split())
    return text