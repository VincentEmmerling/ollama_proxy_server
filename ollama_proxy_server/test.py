import ollama
import time

PROXY_HOST_URL = "http://localhost:8000"
USER = "testuser"
KEY = "testkey"

CUSTOM_HEADERS = {"Authorization": f"Bearer {USER}:{KEY}"}

client = ollama.Client(host=PROXY_HOST_URL, headers=CUSTOM_HEADERS)
no_token_client = ollama.Client(host=PROXY_HOST_URL)

if __name__ == "__main__":
    try:
        response = client.chat(
            model='llama3.2:1b',
            messages=[{'role': 'user', 'content': 'How are you?'}],
        )
        print("Chat Response:")
        print(f"Role: {response['message']['role']}")
        print(f"Content: {response['message']['content']}")
    except ollama.ResponseError as e:
        print(f"Ollama API Error: HTTP Status {e.status_code}")
        print(f"Error details: {e.error}")
    except Exception as e:
        print(f"Error: {e}")
