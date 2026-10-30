"""List AI models with a local key; importing performs no requests."""
import os
import sys


def main():
    api_key = os.environ.get('TITANIUM_AI_KEY')
    if not api_key:
        print('Set TITANIUM_AI_KEY before checking available models.')
        return 1
    from google import genai

    client = genai.Client(api_key=api_key)
    print('Searching for available AI models...')
    try:
        for model in client.models.list():
            if 'generateContent' in (model.supported_actions or []):
                print(f'Found: {model.name}')
    except Exception as exc:
        print(f'Error: {exc}')
        return 1
    return 0


if __name__ == '__main__':
    # Windows consoles default to cp1252/cp1256; force UTF-8 so emoji/Arabic output never crashes
    for _stream in (sys.stdout, sys.stderr):
        if hasattr(_stream, 'reconfigure'):
            _stream.reconfigure(encoding='utf-8', errors='replace')
    sys.exit(main())
