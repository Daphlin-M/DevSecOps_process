import os
import uuid
import time
from datetime import datetime
from dotenv import load_dotenv
from openai import AzureOpenAI
import pandas as pd
import openpyxl
import base64
import os
# from google import genai
# from google.genai import types

load_dotenv()

client = AzureOpenAI(
    azure_endpoint=os.getenv("AZURE_ENDPOINT"),
    api_key=os.getenv("API_KEY"),
    api_version=os.getenv("API_VERSION"),
    azure_deployment=os.getenv("AZURE_DEPLOYMENT")
)

def log_llm_interaction(request_id, prompt, response, start_time, end_time):
    # Text file logging
    log_dir = "outputs"
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, f"llm_log_{datetime.now().strftime('%Y%m%d')}.txt")
    
    with open(log_file, "a") as f:
        f.write("="*40 + "\n")
        f.write(f"Timestamp: {datetime.now().isoformat()}\n")
        f.write(f"Request ID: {request_id}\n")
        f.write(f"Model: gpt-4o-mini\n")
        f.write("-"*40 + "\n")
        f.write("Request:\n")
        f.write(f"  Prompt: {prompt}\n")
        f.write("-"*40 + "\n")
        f.write("Response:\n")
        f.write(f"  Output: {response}\n")
        f.write(f"  Status: success\n")
        f.write(f"  Response Time: {int((end_time - start_time) * 1000)} ms\n")
        f.write("-"*40 + "\n")
        f.write("Metadata:\n")
        f.write("  Project: oracle_to_jasper_conversion\n")
        f.write("  Environment: production\n")
        f.write("="*40 + "\n\n")

    # Excel logging
    excel_log_file = os.path.join(log_dir, f"llm_log_{datetime.now().strftime('%Y%m%d')}.xlsx")
    
    # Create DataFrame for new log entry
    new_log = pd.DataFrame({
        'Timestamp': [datetime.now().isoformat()],
        'Request ID': [request_id],
        'Model': ['gpt-4o-mini'],
        'Prompt': [prompt],
        'Response': [response],
        'Status': ['success'],
        'Response Time (ms)': [int((end_time - start_time) * 1000)],
        'Project': ['oracle_to_jasper_conversion'],
        'Environment': ['production']
    })

    # If excel file exists, append to it, otherwise create new
    try:
        existing_df = pd.read_excel(excel_log_file)
        updated_df = pd.concat([existing_df, new_log], ignore_index=True)
    except FileNotFoundError:
        updated_df = new_log

    # Save to Excel
    updated_df.to_excel(excel_log_file, index=False)

def call_gpt(prompt):
    print("CALLED LLM")
    request_id = str(uuid.uuid4())
    start_time = time.time()
    
    response = client.chat.completions.create(
        model='gpt-4o-mini',
        messages=[
            {"role": "system", "content": "You are a expert who knows all the minor details of the conversion of Oracle XML file to Jasper JRXML file."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.3
    )
    
    end_time = time.time()
    response_content = response.choices[0].message.content
    # response_content = call_gemini(prompt)
    # end_time = time.time()
    
    log_llm_interaction(request_id, prompt, response_content, start_time, end_time)
    
    print("\n---------------------\n"+response_content+"\n---------------------\n")
    return response_content


def call_gemini(prompt):
    client = genai.Client(
        api_key="AIzaSyDs_XaVu_kOESiL8dq9fViNoVcr6t1mqp8",
    )

    model = "gemini-2.0-pro-exp-02-05"
    contents = [
        types.Content(
            role="user",
            parts=[
                types.Part.from_text(
                    text=f"""{prompt}"""
                ),
            ],
        ),
    ]
    generate_content_config = types.GenerateContentConfig(
        temperature=0.5,
        top_p=0.95,
        top_k=64,
        max_output_tokens=8192,
        response_mime_type="text/plain",
    )

    response_text = ""
    for chunk in client.models.generate_content_stream(
        model=model,
        contents=contents,
        config=generate_content_config,
    ):
        response_text += chunk.text  # Accumulate the chunks

    return response_text