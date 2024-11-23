import requests
import os 

def get_iam_token(auth):
    url = 'https://iam.api.cloud.yandex.net/iam/v1/tokens'
    data = { "yandexPassportOauthToken": auth }
    response = requests.post(url, json=data)
    if response.status_code == 200:
        return response.json().get('iamToken')
    return 


def check_valid_token():
    url = 'https://vulners.com/api/v3/search/lucene/'
    data = {
        "query": "Cisco",
        "apiKey": os.getenv('API_KEY')
    }
    response = requests.post(url, json=data)
    assert response.status_code == 200, f"Unexpected status code: {response.status_code}"


def detect_lang(text, iam_token, folder_id):
    url = 'https://translate.api.cloud.yandex.net/translate/v2/detect'
    data = {
        "text": text,
        "languageCodeHints": [
            'ru', 'en'
        ],
        "folderId": folder_id
    }
    response = requests.post(url, json=data, headers={"Authorization": f"Bearer {iam_token}"})
    if response.status_code == 200:
        return response.json().get('languageCode', None)
    return 


def translate_description(text, targetLanguageCode='ru'):
    iam_token = get_iam_token(os.getenv('AUTH'))
    check_valid_token()
    folder_id = os.getenv('FOLDER_ID')
    text_leng = detect_lang(text, iam_token, folder_id)
    url = 'https://translate.api.cloud.yandex.net/translate/v2/translate'
    data = {
        "sourceLanguageCode": text_leng,
        "targetLanguageCode": targetLanguageCode,
        "texts": [ text ],
        "folderId": folder_id, 
        "speller": True
    }
    response = requests.post(url=url, json=data, headers={"Authorization": f"Bearer {iam_token}"})
    if response.status_code == 200:
        return response.json().get('translations')[0].get('text', None)
    return
