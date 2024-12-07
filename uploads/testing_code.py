import json
import csv
from shodan import Shodan, APIError
from pymongo import MongoClient
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
# Gerekli kütüphaneler
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

def standalone_function():
    print("This is a standalone function")

class ElasticSearchNoAuth:
    def __init__(self):
        self.api = Shodan('')
        self.limit = 0
        self.es_urls = []

    @staticmethod
    def list_indices(es_url, timeout=5, retries=3):
        attempt = 0
        while attempt < retries:
            try:
                response = requests.get(f'{es_url}/_cat/indices?format=json', timeout=timeout)
                response.raise_for_status()
                return [index['index'] for index in response.json()]
            except requests.exceptions.Timeout:
                print(f"Connection to {es_url} timed out. Retrying... ({attempt + 1}/{retries})")
                attempt += 1
            except requests.exceptions.RequestException as err:
                print(f"HTTP error occurred: {err}")
                return []
            except Exception as err:
                print(f"Other error occurred: {err}")
                return []
        return []

    @staticmethod
    def search_index(es_url, index_name, query, size=500, timeout=5):
        try:
            response = requests.get(f'{es_url}/{index_name}/_search', json=query, params={'size': size}, timeout=timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as http_err:
            print(f'HTTP error occurred: {http_err}')
            print(response.text)
            return {}
        except Exception as err:
            print(f'Other error occurred: {err}')
            return {}

    def get_shodan(self, workers):
        self.limit = workers
        try:
            results = self.api.search_cursor('elasticsearch -authentication')
            if results:
                for banner in results:
                    try:
                        ip = banner.get('ip_str')
                        country_code = banner.get('location', {}).get('country_code')
                        port = banner.get('port')

                        if not ip or not port:
                            print("IP address or port not found in the banner.")
                            continue

                        es_url = f'http://{ip}:{port}'
                        self.es_urls.append({'url': es_url, 'ip': ip, 'port': port})
                        print(f"{ip} || {country_code} || {port}")

                        if len(self.es_urls) >= self.limit:
                            break
                    except (KeyError, TypeError, json.JSONDecodeError) as e:
                        print(f"Error parsing Shodan banner: {e}")
                        continue
            else:
                print("No results from Shodan API.")

        except APIError as e:
            print(f"Shodan API Error: {e}")
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def dump_index_to_csv(self, es_url, ip, port, index_name):
        query = {'query': {'match_all': {}}}
        response = self.search_index(es_url, index_name, query)

        if not response:
            print(f"Error retrieving data from index '{index_name}' on {es_url}.")
            return

        csv_filename = f"{ip}_{port}_{index_name}.csv"

        try:
            with open(csv_filename, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)

                headers_written = False
                for hit in response.get('hits', {}).get('hits', []):
                    document = hit.get('_source', {})
                    if not headers_written:
                        headers = list(document.keys())
                        writer.writerow(headers)
                        headers_written = True

                    writer.writerow(list(document.values()))

            print(f"Index '{index_name}' saved to '{csv_filename}'.")
        except Exception as e:
            print(f"Error writing to CSV file: {e}")

    def run_elastic_search_auth_proc(self, workers):
        try:
            self.get_shodan(workers)
            if not self.es_urls:
                print("No Elasticsearch instances found.")
                return

            for es_data in self.es_urls:
                es_url = es_data['url']
                ip = es_data['ip']
                port = es_data['port']

                available_indices = self.list_indices(es_url)
                if not available_indices:
                    print(f"No indices found for {es_url} or an error occurred.")
                    continue

                print(f"Available indexes for {es_url}: {available_indices}")

                with ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = [
                        executor.submit(self.dump_index_to_csv, es_url, ip, port, index_name)
                        for index_name in available_indices
                    ]

                    for future in as_completed(futures):
                        try:
                            future.result()
                        except Exception as e:
                            print(f"An error occurred during the thread execution: {e}")

        except Exception as e:
            print(f"An unexpected error occurred with Elasticsearch: {e}")

class MongoDBNoAuth:
    def __init__(self):
        self.api = Shodan('')
        self.limit = 0
        self.mongo_urls = []

    def get_shodan(self, workers):
        self.limit = workers
        try:
            results = self.api.search_cursor('"MongoDB Server Information" port:27017 -authentication')
            if results:
                for banner in results:
                    try:
                        ip = banner.get('ip_str')
                        country_code = banner.get('location', {}).get('country_code')
                        port = banner.get('port')

                        if not ip or not port:
                            print("IP address or port not found in the banner.")
                            continue

                        mongo_url = f'mongodb://{ip}:{port}/'
                        self.mongo_urls.append({'url': mongo_url, 'ip': ip, 'port': port})
                        print(f"{ip} || {country_code} || {port}")

                        if len(self.mongo_urls) >= self.limit:
                            break
                    except (KeyError, TypeError, json.JSONDecodeError) as e:
                        print(f"Error parsing Shodan banner: {e}")
                        continue
            else:
                print("No results from Shodan API.")

        except APIError as e:
            print(f"Shodan API Error: {e}")
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def dump_collection_to_csv(self, mongo_url, ip, port, db_name, collection_name):
        try:
            client = MongoClient(mongo_url, serverSelectionTimeoutMS=4000)
            db = client[db_name]
            collection = db[collection_name]
            documents = collection.find()

            csv_filename = f"{ip}_{port}_{db_name}_{collection_name}.csv"

            with open(csv_filename, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)

                headers_written = False
                for document in documents:
                    if not headers_written:
                        headers = list(document.keys())
                        writer.writerow(headers)
                        headers_written = True

                    writer.writerow(list(document.values()))

            print(f"Collection '{collection_name}' from database '{db_name}' saved to '{csv_filename}'.")

        except Exception as e:
            print(f"An error occurred while dumping collection '{collection_name}' from database '{db_name}': {e}")

    def run_mongo_auth_proc(self, workers):
        try:
            self.get_shodan(workers)
            if not self.mongo_urls:
                print("No MongoDB instances found.")
                return

            for mongo_data in self.mongo_urls:
                mongo_url = mongo_data['url']
                ip = mongo_data['ip']
                port = mongo_data['port']

                try:
                    client = MongoClient(mongo_url, serverSelectionTimeoutMS=4000)  # 4-second timeout
                    databases = client.list_database_names()

                    print(f"Databases in {mongo_url}: {databases}")

                    for db_name in databases:
                        collections = client[db_name].list_collection_names()

                        with ThreadPoolExecutor(max_workers=workers) as executor:
                            futures = [
                                executor.submit(self.dump_collection_to_csv, mongo_url, ip, port, db_name, collection_name)
                                for collection_name in collections
                            ]

                            for future in as_completed(futures):
                                try:
                                    future.result()
                                except Exception as e:
                                    print(f"An error occurred during the thread execution: {e}")

                except Exception as e:
                    print(f"An error occurred while processing MongoDB instance {mongo_url}: {e}")

        except Exception as e:
            print(f"An unexpected error occurred: {e}")

class Bug:
    def __init__(self, bug_id, description):
        self.bug_id = bug_id
        self.description = description

    def display_info(self):
        return f"Bug ID: {self.bug_id}, Description: {self.description}"


class BugClassifier:
    def __init__(self, classification):
        self.classification = classification

    def classify_bug(self, bug):
        # Basit bir sınıflandırma mantığı
        if "security" in bug.description.lower():
            return "Security Issue"
        elif "error" in bug.description.lower():
            return "Error"
        else:
            return "General Issue"


# Dışarıda tanımlanan metot
def analyze_bug(bug):
    # Hata analizini simüle eden bir metot
    if "leak" in bug.description.lower():
        return "Potential memory leak detected."
    return "No issues detected."

service = Service(ChromeDriverManager().install())
driver = webdriver.Chrome(service=service)

try:
    # 1. Arızalı Araba Oylama sitesine gidiyoruz
    driver.get('https://buggy.justtestit.org/')
    # Sayfanın yüklendiğinden emin olmak için en az 10 saniye bekliyoruz

    # 2. Giriş bilgilerini giriyoruz
    username_input = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.NAME, 'login'))
    )
    password_input = driver.find_element(By.NAME, 'password')

    username_input.send_keys('asd98')  # Kullanıcı adınızı buraya giriyoruz
    password_input.send_keys('123456Asd-')  # Şifrenizi buraya giriyoruz

    submit_button = driver.find_element(By.XPATH, "//button[contains(text(),'Login')]")
    submit_button.click()

    # 3. Girişin başarılı olduğunu "Profile" bağlantısını kontrol ederek doğruluyoruz
    profile_link = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.XPATH, "//a[contains(text(),'Profile')]"))
    )
    print("Giriş başarılı!")


    # 4. Modeller sayfasını görüntülüyoruz
    model_link = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.XPATH, "//a[@href='/overall']"))
    )
    model_link.click()

    # 5. Zonda modelini buluyoruz
    zonda_link = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.XPATH, "//a[contains(text(), 'Zonda')]"))
    )
    zonda_link.click()

    # 6. Bir yorum ile oy gönderiyoruz
    comment_input = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.ID, 'comment'))
    )
    comment_input.send_keys('Nice car!')

    vote_button = WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.XPATH, "//button[@class='btn btn-success']"))
    )
    vote_button.click()

    # 7. "Thank you for your vote!" mesajını bekliyoruz
    success_message = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.XPATH, "//p[contains(text(),'Thank you for your vote!')]"))
    )

    assert 'Thank you for your vote!' in success_message.text
    print("Oy başarıyla gönderildi!")

except Exception as e:
    print(f"Test sırasında bir hata oluştu: {e}")

finally:
    # Tarayıcıyı 5 saniye sonra kapatıyoruz
    time.sleep(5)
    driver.quit()
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

service = Service(ChromeDriverManager().install())
options = webdriver.ChromeOptions()
driver = webdriver.Chrome(service=service, options=options)

try:
    driver.get('https://buggy.justtestit.org/')

    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.NAME, 'login')))

    username_input = driver.find_element(By.NAME, 'login')
    password_input = driver.find_element(By.NAME, 'password')

    username_input.send_keys('Denemee')
    password_input.send_keys('Deneme1234!')

    submit_button = driver.find_element(By.XPATH, "//button[contains(text(),'Login')]")
    submit_button.click()

    profile_link = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.XPATH, "//a[contains(text(),'Profile')]"))
    )

    print("Giris")

    time.sleep(3)

    overall_link = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.XPATH, "//a[@href='/overall']"))
    )
    driver.execute_script("arguments[0].click();", overall_link)

    page = 1
    while True:
        try:
            print(f'Bu {page} Sayfadayız ')

            table = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, 'table'))
            )
            rows = table.find_elements(By.TAG_NAME, 'tr')

            print(f'Sayfa {page}: {len(rows) - 1} bulundu')
            for row in rows[1:]:
                columns = row.find_elements(By.TAG_NAME, 'td')
                for column in columns:
                    print(column.text, end=' / ')
                print()

            next_button = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.XPATH, "//a[@class='btn' and text()='»']"))
            )
            next_button.click()

            time.sleep(3)

            page += 1

        except Exception as e:
            print(f'Hata Olustu {e}')
            break
except Exception as e:
    print(f"Hata var: {e}")
finally:
    driver.quit()

# Örnek kullanımı
if __name__ == "__main__":
    standalone_function()


