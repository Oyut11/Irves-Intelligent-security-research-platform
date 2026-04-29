import asyncio
from litellm import completion

async def test():
    print("Testing ollama/ prefix...")
    try:
        response = completion(
            model="ollama/deepseek-r1:8b",
            messages=[{"role": "user", "content": "Hi"}],
            api_base="http://localhost:11434",
            api_key="dummy"
        )
        print("ollama/ success!", response.choices[0].message.content)
    except Exception as e:
        print("ollama/ failed:", e)

    print("\nTesting openai/ prefix...")
    try:
        response = completion(
            model="openai/deepseek-r1:8b",
            messages=[{"role": "user", "content": "Hi"}],
            api_base="http://localhost:11434",
            api_key="dummy"
        )
        print("openai/ success!", response.choices[0].message.content)
    except Exception as e:
        print("openai/ failed:", e)

asyncio.run(test())
