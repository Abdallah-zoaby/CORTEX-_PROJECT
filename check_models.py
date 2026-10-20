"""List AI models with a local key; importing performs no requests."""
import os
import sys


def main():
    api_key = os.environ.get('TITANIUM_AI_KEY')
    if not api_key:
        print('Set TITANIUM_AI_KEY before checking available models.')
        return 1
    import google.generativeai as genai

    genai.configure(api_key=api_key)
    print('Searching for available AI models...')
    try:
        for model in genai.list_models():
            if 'generateContent' in model.supported_generation_methods:
                print(f'Found: {model.name}')
    except Exception as exc:
        print(f'Error: {exc}')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
