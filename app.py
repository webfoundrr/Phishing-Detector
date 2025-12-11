import streamlit as st
import numpy as np
import pandas as pd
import re
import math
import requests
import joblib
import os
import socket
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from requests.exceptions import RequestException, Timeout, ConnectionError, SSLError, TooManyRedirects

try:
    import idna
    IDNA_AVAILABLE = True
except ImportError:
    IDNA_AVAILABLE = False

st.set_page_config(
    page_title="CyberShield AI | Phishing Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    /* Основной фон и шрифты */
    .stApp {
        background-color: #0e1117;
    }
    
    /* Стилизация заголовка */
    h1 {
        color: #00ff41;
        font-family: 'Courier New', Courier, monospace;
        text-shadow: 0 0 10px #00ff41;
    }
    
    /* Карточки результатов */
    .result-card {
        padding: 30px;
        border-radius: 15px;
        margin-top: 20px;
        text-align: center;
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.4);
        backdrop-filter: blur(10px);
    }
    
    .safe {
        background-color: rgba(46, 204, 113, 0.2);
        border: 2px solid #2ecc71;
        color: #2ecc71;
    }
    
    .danger {
        background-color: rgba(231, 76, 60, 0.2);
        border: 2px solid #e74c3c;
        color: #e74c3c;
        animation: pulse 2s infinite;
    }
    
    .suspicious {
        background-color: rgba(241, 196, 15, 0.2);
        border: 2px solid #f1c40f;
        color: #f1c40f;
    }

    @keyframes pulse {
        0% { box-shadow: 0 0 0 0 rgba(231, 76, 60, 0.4); }
        70% { box-shadow: 0 0 0 10px rgba(231, 76, 60, 0); }
        100% { box-shadow: 0 0 0 0 rgba(231, 76, 60, 0); }
    }
</style>
""", unsafe_allow_html=True)

def calculate_entropy(text):
    if not text:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def is_known_legitimate_domain(hostname):
    if not hostname:
        return False
    
    hostname_lower = hostname.lower()
    known_domains = [
        'instagram.com', 'facebook.com', 'google.com', 'gmail.com', 'github.com', 
        'microsoft.com', 'apple.com', 'amazon.com', 'twitter.com',
        'linkedin.com', 'youtube.com', 'netflix.com', 'paypal.com',
        'telegram.org',
        'yandex.ru', 'ya.ru', 'mail.ru', 'rambler.ru', 'km.ru', 'qip.ru',
        'vk.com', 'ok.ru', 'livejournal.com', 'my.mail.ru',
        'ria.ru', 'tass.ru', 'kommersant.ru', 'iz.ru', 'rg.ru', 'lenta.ru',
        'gazeta.ru', 'rt.com', 'mk.ru', 'rbc.ru', 'vedomosti.ru', 'forbes.ru',
        'takiedela.ru', 'meduza.io', 'novayagazeta.ru', 'fontanka.ru', '74.ru',
        'baikal24.ru', 'chelob.ru', 'sibirrealty.ru',
        'rutube.ru', 'smotrim.ru', 'ivi.ru', 'kinopoisk.ru', 'more.tv',
        'start.ru', 'premier.ru', 'okko.tv', 'megogo.ru', 'amediateka.ru',
        'wildberries.ru', 'wildberries.com', 'ozon.ru', 'market.yandex.ru', 'aliexpress.ru',
        'citilink.ru', 'mvideo.ru', 'dns-shop.ru', 'eldorado.ru', 'lamoda.ru',
        'beru.ru', 'ulmart.ru', 'svyaznoy.ru', 'technopark.ru', 'obi.ru',
        'auchan.ru', 'lenta.com', 'magnit.ru', 'perekrestok.ru', '5ka.ru',
        'sberbank.ru', 'vtb.ru', 'alfabank.ru', 'tinkoff.ru', 'gazprombank.ru',
        'raiffeisen.ru', 'open.ru', 'sovcombank.ru', 'pochtabank.ru', 'rshb.ru',
        'mkb.ru', 'homecredit.ru', 'rsb.ru', 'yoomoney.ru', 'vbr.ru', 'tbank.ru',
        'gosuslugi.ru', 'nalog.ru', 'pfr.gov.ru', 'fss.ru', 'rosreestr.ru',
        'minzdrav.gov.ru', 'minobrnauki.gov.ru', 'economy.gov.ru',
        'uchi.ru', 'yaklass.ru', 'foxford.ru', 'gb.ru', 'netology.ru',
        'skillbox.ru', 'stepik.org', 'openedu.ru', 'lektorium.tv',
        'arzamas.academy', 'postnauka.ru', 'intuit.ru', 'universarium.org',
        'resh.edu.ru', 'mos.ru',
        'hh.ru', 'superjob.ru', 'rabota.ru', 'avito.ru', 'zarplata.ru',
        'trud.com', 'unity.ru', 'gorodrabot.ru', 'rabotamail.ru',
        'cian.ru', 'yard.ru', 'mirkvartir.ru', 'domclick.ru', 'ngs.ru',
        'etagi.com', 'youla.ru',
        'auto.ru', 'drom.ru', 'cars.ru', 'car.ru', 'zr.ru', 'autoreview.ru',
        'kolesa.ru', 'abw.by', 'mladsha.ru', 'avtopodbor.ru', 'autostat.ru',
        'autovesti.ru',
        'sberhealth.ru', 'napopravku.ru', 'prodoctorov.ru', 'medportal.ru',
        'stomatologii.ru', 'apteki.ru', 'eapteka.ru', 'health.mail.ru',
        'medicina.ru',
        'store.steampowered.com', 'kanobu.ru', 'stopgame.ru', 'igromania.ru',
        'gamexp.ru', 'gmbox.ru', 'ag.ru', 'playground.ru', 'riotgames.com',
        'worldoftanks.ru', 'worldofwarships.ru', 'cfire.mail.ru', 'warthunder.ru',
        'eda.ru', 'recepty.ru', 'povarenok.ru', 'gotovim-doma.ru', 'menu.ru',
        'delivery-club.ru', 'sbermarket.ru',
        'championat.com', 'sport-express.ru', 'sports.ru', 'matchtv.ru',
        'sportbox.ru', 'rfs.ru', 'fnl.ru', 'khl.ru', 'ffr.ru', 'volley.ru',
        'russiabasket.ru', 'tennis-russia.ru',
        'music.yandex.ru', 'zvuk.com', 'boom.ru', 'stereo.ru',
        'habr.com', '3dnews.ru', 'ixbt.com', 'cnews.ru', 'server.ru',
        'hosting.ru', 'reg.ru', 'nic.ru', 'timeweb.com', 'beget.com',
        'sprinthost.ru', 'firstvds.ru', 'selectel.ru', 'cloud.ru',
        'pikabu.ru', 'yaplakal.com', 'dirty.ru', 'fishki.net', 'beha.ru',
        'kp.ru', 'aif.ru', 'vm.ru', 'spbdnevnik.ru', 'nevnov.ru', '47news.ru',
        'gorod-plus.tv', 'online47.ru', 'lentv24.ru', 'moika78.ru', '78.ru',
        '5-tv.ru', 'saint-petersburg.ru', 'peterburg2.ru', 'spbinfo.ru',
        'karpovka.com', 'newkaliningrad.ru', 'klops.ru', 'kaliningrad.ru',
        'rugrad.eu', 'kgd.ru', 'drugoigorod.ru', 'samaratoday.ru',
        'progorodsamara.ru', 'volgnews.ru', 'sgpress.ru', '63.ru', 'niasamara.ru',
        'irr.ru', 'kufar.by', 'tut.by', 'onliner.by', '2gis.ru', 'nigma.ru',
        'sputnik.ru', 'gismeteo.ru'
    ]
    
    return any(
        hostname_lower == domain or 
        hostname_lower.endswith('.' + domain) or 
        (hostname_lower.endswith(domain) and (len(hostname_lower) == len(domain) or hostname_lower[-(len(domain)+1)] == '.'))
        for domain in known_domains
    )

def check_site_availability(url, timeout=5, is_known_domain=False):
    try:
        response = requests.head(url, timeout=timeout, allow_redirects=True, verify=False)
        if response.status_code == 405:
            response = requests.get(url, timeout=timeout, allow_redirects=True, verify=False, stream=True)
        
        if is_known_domain:
            return True, "Сайт доступен", response.status_code
        
        if response.status_code >= 400:
            if response.status_code == 404:
                return True, "Сайт доступен (страница не найдена)", response.status_code
            elif response.status_code == 403:
                return True, "Сайт доступен (доступ ограничен)", response.status_code
            elif response.status_code in [418, 429]:
                return True, f"Сайт доступен (код {response.status_code})", response.status_code
            elif response.status_code in [503, 502, 504]:
                return True, f"Сайт доступен (временно недоступен, код {response.status_code})", response.status_code
            elif response.status_code >= 500:
                return True, f"Сайт доступен (ошибка сервера {response.status_code})", response.status_code
            else:
                return True, f"Сайт доступен (код {response.status_code})", response.status_code
        
        return True, "Сайт доступен", response.status_code
    
    except Timeout:
        if is_known_domain:
            return True, "Сайт доступен (таймаут при проверке)", None
        return False, "Таймаут подключения - сайт не отвечает", None
    except ConnectionError as e:
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc or parsed.path.split('/')[0]
            socket.gethostbyname(hostname)
            if is_known_domain:
                return True, "Сайт доступен (проблема с подключением)", None
            return False, "Ошибка подключения к серверу", None
        except socket.gaierror:
            return False, "Домен не существует (DNS ошибка)", None
        except:
            if is_known_domain:
                return True, "Сайт доступен (ошибка подключения)", None
            return False, "Ошибка подключения", None
    except SSLError:
        try:
            http_url = url.replace('https://', 'http://')
            response = requests.head(http_url, timeout=timeout, allow_redirects=True, verify=False)
            return True, "Сайт доступен (HTTP, без SSL)", response.status_code
        except:
            if is_known_domain:
                return True, "Сайт доступен (проблема с SSL)", None
            return False, "Ошибка SSL и HTTP недоступен", None
    except TooManyRedirects:
        return True, "Сайт доступен (много редиректов)", None
    except RequestException as e:
        if is_known_domain:
            return True, "Сайт доступен (ошибка запроса)", None
        return False, f"Ошибка запроса: {str(e)[:50]}", None
    except Exception as e:
        if is_known_domain:
            return True, "Сайт доступен", None
        return False, f"Неизвестная ошибка: {str(e)[:50]}", None

def normalize_hostname(hostname):
    if not hostname:
        return hostname
    
    try:
        if hostname.startswith('xn--'):
            parts = hostname.split('.')
            normalized_parts = []
            for part in parts:
                if part.startswith('xn--'):
                    try:
                        if IDNA_AVAILABLE:
                            decoded = idna.decode(part.encode('ascii'))
                            normalized_parts.append(decoded)
                        else:
                            if part == 'xn--p1ai':
                                normalized_parts.append('рф')
                            else:
                                normalized_parts.append(part)
                    except:
                        normalized_parts.append(part)
                else:
                    normalized_parts.append(part)
            return '.'.join(normalized_parts)
    except:
        pass
    
    return hostname

def extract_features(url):
    features = []
    
    if not re.match(r'^https?://', url):
        parse_url = 'http://' + url
    else:
        parse_url = url

    try:
        parsed = urlparse(parse_url)
        hostname = parsed.netloc
        path = parsed.path
    except:
        hostname = ""
        path = ""

    hostname_normalized = normalize_hostname(hostname)
    hostname_lower = hostname_normalized.lower() if hostname_normalized else ""
    path = path.lower() if path else ""

    ip_pattern = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)
    features.append(1 if ip_pattern else 0)
    
    features.append(1 if len(url) > 75 else 0)
    
    short_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd']
    is_short_url = any(short in hostname_lower for short in short_domains)
    features.append(1 if is_short_url else 0)
    
    features.append(1 if '@' in url else 0)
    
    if '://' in url:
        after_protocol = url.split('://', 1)[1]
        features.append(1 if '//' in after_protocol else 0)
    else:
        features.append(0)
    
    if hostname:
        has_prefix_suffix = hostname.startswith('-') or hostname.endswith('-')
        if not has_prefix_suffix:
            for part in hostname.split('.'):
                if part.startswith('-') or part.endswith('-'):
                    has_prefix_suffix = True
                    break
        features.append(1 if has_prefix_suffix else 0)
    else:
        features.append(0)
    
    if hostname:
        subdomain_count = hostname.count('.') - 1
        features.append(subdomain_count)
    else:
        features.append(0)
    
    features.append(1 if parsed.scheme == 'https' else 0)
    
    if hostname:
        domain_parts = hostname.split('.')
        if len(domain_parts) > 1:
            main_domain = '.'.join(domain_parts[:-1])
            domain_len = len(main_domain)
        else:
            domain_len = len(hostname)
        known_short_domains = ['ya.ru', 'go.com', 'tv', 'io', 'ai', 'me', 'co', 'cc']
        if any(short in hostname_lower for short in known_short_domains):
            features.append(max(domain_len, 4))
        else:
            features.append(domain_len)
    else:
        features.append(0)
    
    if hostname and ':' in hostname:
        try:
            port = int(hostname.split(':')[1])
            features.append(1 if port not in [80, 443, 8080] else 0)
        except:
            features.append(0)
    else:
        features.append(0)
    
    special_chars = ['%', '&', '=', '?', '#', '+']
    special_count = sum(url.count(char) for char in special_chars)
    features.append(1 if special_count > 3 else 0)
    
    features.append(calculate_entropy(hostname))
    
    suspicious_words = ['verify', 'update', 'secure', 'confirm', 'validate']
    path_suspicious = ['login', 'account', 'bank']
    
    known_domains = [
        'instagram.com', 'facebook.com', 'google.com', 'gmail.com', 'github.com', 
        'microsoft.com', 'apple.com', 'amazon.com', 'twitter.com',
        'linkedin.com', 'youtube.com', 'netflix.com', 'paypal.com',
        'telegram.org',
        'yandex.ru', 'ya.ru', 'mail.ru', 'rambler.ru', 'km.ru', 'qip.ru',
        'vk.com', 'ok.ru', 'livejournal.com', 'my.mail.ru',
        'ria.ru', 'tass.ru', 'kommersant.ru', 'iz.ru', 'rg.ru', 'lenta.ru',
        'gazeta.ru', 'rt.com', 'mk.ru', 'rbc.ru', 'vedomosti.ru', 'forbes.ru',
        'takiedela.ru', 'meduza.io', 'novayagazeta.ru', 'fontanka.ru', '74.ru',
        'baikal24.ru', 'chelob.ru', 'sibirrealty.ru',
        'rutube.ru', 'smotrim.ru', 'ivi.ru', 'kinopoisk.ru', 'more.tv',
        'start.ru', 'premier.ru', 'okko.tv', 'megogo.ru', 'amediateka.ru',
        'wildberries.ru', 'wildberries.com', 'ozon.ru', 'market.yandex.ru', 'aliexpress.ru',
        'citilink.ru', 'mvideo.ru', 'dns-shop.ru', 'eldorado.ru', 'lamoda.ru',
        'beru.ru', 'ulmart.ru', 'svyaznoy.ru', 'technopark.ru', 'obi.ru',
        'auchan.ru', 'lenta.com', 'magnit.ru', 'perekrestok.ru', '5ka.ru',
        'sberbank.ru', 'vtb.ru', 'alfabank.ru', 'tinkoff.ru', 'gazprombank.ru',
        'raiffeisen.ru', 'open.ru', 'sovcombank.ru', 'pochtabank.ru', 'rshb.ru',
        'mkb.ru', 'homecredit.ru', 'rsb.ru', 'yoomoney.ru', 'vbr.ru', 'tbank.ru',
        'gosuslugi.ru', 'nalog.ru', 'pfr.gov.ru', 'fss.ru', 'rosreestr.ru',
        'minzdrav.gov.ru', 'minobrnauki.gov.ru', 'economy.gov.ru',
        'uchi.ru', 'yaklass.ru', 'foxford.ru', 'gb.ru', 'netology.ru',
        'skillbox.ru', 'stepik.org', 'openedu.ru', 'lektorium.tv',
        'arzamas.academy', 'postnauka.ru', 'intuit.ru', 'universarium.org',
        'resh.edu.ru', 'mos.ru',
        'hh.ru', 'superjob.ru', 'rabota.ru', 'avito.ru', 'zarplata.ru',
        'trud.com', 'unity.ru', 'gorodrabot.ru', 'rabotamail.ru',
        'cian.ru', 'yard.ru', 'mirkvartir.ru', 'domclick.ru', 'ngs.ru',
        'etagi.com', 'youla.ru',
        'auto.ru', 'drom.ru', 'cars.ru', 'car.ru', 'zr.ru', 'autoreview.ru',
        'kolesa.ru', 'abw.by', 'mladsha.ru', 'avtopodbor.ru', 'autostat.ru',
        'autovesti.ru',
        'sberhealth.ru', 'napopravku.ru', 'prodoctorov.ru', 'medportal.ru',
        'stomatologii.ru', 'apteki.ru', 'eapteka.ru', 'health.mail.ru',
        'medicina.ru',
        'store.steampowered.com', 'kanobu.ru', 'stopgame.ru', 'igromania.ru',
        'gamexp.ru', 'gmbox.ru', 'ag.ru', 'playground.ru', 'riotgames.com',
        'worldoftanks.ru', 'worldofwarships.ru', 'cfire.mail.ru', 'warthunder.ru',
        'eda.ru', 'recepty.ru', 'povarenok.ru', 'gotovim-doma.ru', 'menu.ru',
        'delivery-club.ru', 'sbermarket.ru',
        'championat.com', 'sport-express.ru', 'sports.ru', 'matchtv.ru',
        'sportbox.ru', 'rfs.ru', 'fnl.ru', 'khl.ru', 'ffr.ru', 'volley.ru',
        'russiabasket.ru', 'tennis-russia.ru',
        'music.yandex.ru', 'zvuk.com', 'boom.ru', 'stereo.ru',
        'habr.com', '3dnews.ru', 'ixbt.com', 'cnews.ru', 'server.ru',
        'hosting.ru', 'reg.ru', 'nic.ru', 'timeweb.com', 'beget.com',
        'sprinthost.ru', 'firstvds.ru', 'selectel.ru', 'cloud.ru',
        'pikabu.ru', 'yaplakal.com', 'dirty.ru', 'fishki.net', 'beha.ru',
        'kp.ru', 'aif.ru', 'vm.ru', 'spbdnevnik.ru', 'nevnov.ru', '47news.ru',
        'gorod-plus.tv', 'online47.ru', 'lentv24.ru', 'moika78.ru', '78.ru',
        '5-tv.ru', 'saint-petersburg.ru', 'peterburg2.ru', 'spbinfo.ru',
        'karpovka.com', 'newkaliningrad.ru', 'klops.ru', 'kaliningrad.ru',
        'rugrad.eu', 'kgd.ru', 'drugoigorod.ru', 'samaratoday.ru',
        'progorodsamara.ru', 'volgnews.ru', 'sgpress.ru', '63.ru', 'niasamara.ru',
        'irr.ru', 'kufar.by', 'tut.by', 'onliner.by', '2gis.ru', 'nigma.ru',
        'sputnik.ru', 'yandex.ru', 'gismeteo.ru',
        'екатеринбург.рф', 'москва.рф', 'спб.рф', 'санкт-петербург.рф',
        'школа.рф', 'гимназия.рф', 'лицей.рф',
        'edu.ru', 'school.edu.ru', 'gymnasium.edu.ru', 'lyceum.edu.ru'
    ]
    
    is_educational = False
    if hostname_lower:
        educational_tlds = ['.рф', '.edu.ru', '.edu', '.school']
        if any(hostname_lower.endswith(tld) for tld in educational_tlds):
            is_educational = True
        
        educational_keywords = ['школа', 'гимназия', 'лицей', 'университет', 'институт', 
                               'колледж', 'училище', 'school', 'gymnasium', 'lyceum', 
                               'university', 'college', 'edu', 'екатеринбург', 'москва']
        if any(keyword in hostname_lower for keyword in educational_keywords):
            is_educational = True
    
    is_known_domain = any(
        hostname_lower == domain or 
        hostname_lower.endswith('.' + domain) or 
        (hostname_lower.endswith(domain) and (len(hostname_lower) == len(domain) or hostname_lower[-(len(domain)+1)] == '.'))
        for domain in known_domains
    )
    
    if is_educational:
        is_known_domain = True
    
    count_suspicious = sum(1 for word in suspicious_words if word in url.lower())
    
    if not is_known_domain:
        count_suspicious += sum(1 for word in path_suspicious if word in path and word not in hostname_lower)
    
    features.append(count_suspicious)
    features.append(1 if is_known_domain else 0)
    features.append(hostname.count('-') if hostname else 0)

    return features

@st.cache_resource
def load_and_train_model(use_csv=False):
    data = []
    labels = []
    total_loaded = 0
    
    if use_csv:
        csv_files = [
            ('malicious_phish.csv', 'type'),
            ('legitimate_dataset.csv', 'label'),
            ('dataset_example.csv', 'label')
        ]
        
        for csv_path, label_column in csv_files:
            try:
                if os.path.exists(csv_path):
                    df = pd.read_csv(csv_path)
                    
                    if 'url' not in df.columns:
                        st.warning(f"⚠️ Файл {csv_path} не содержит колонку 'url'. Пропущен.")
                        continue
                    
                    file_count = 0
                    for _, row in df.iterrows():
                        url = str(row['url']).strip()
                        if not url or url == 'nan':
                            continue
                        
                        if label_column == 'type':
                            url_type = str(row['type']).strip().lower()
                            if url_type in ['phishing', 'defacement', 'malware']:
                                label = 1
                            elif url_type == 'benign':
                                label = 0
                            else:
                                continue
                        else:
                            label = int(row[label_column])
                        
                        data.append(extract_features(url))
                        labels.append(label)
                        file_count += 1
                    
                    total_loaded += file_count
                    st.info(f"📊 Загружено {file_count:,} записей из {csv_path}")
                else:
                    st.warning(f"⚠️ Файл {csv_path} не найден. Пропущен.")
            except Exception as e:
                st.warning(f"⚠️ Ошибка загрузки {csv_path}: {e}. Пропущен.")
        
        if total_loaded == 0:
            st.warning("⚠️ Не удалось загрузить данные из CSV файлов. Используются встроенные данные.")
            use_csv = False
    
    if not use_csv:
        phishing_urls = [
            "http://secure-login-apple-id.com.verify.account.qwe89.com",
            "http://192.168.1.1/update/bank/login",
            "https://paypal-secure-check.com/signin?user=admin",
            "http://google-drive-secure.login-attempt.net",
            "https://netflix-payment-update.required.com.br",
            "http://sberbank-online-verify.tk",
            "https://vk-admin-login.support-service.ru/auth",
            "http://secure-login.sberbank-verify.tk"
        ]
        legit_urls = [
            "https://www.google.com",
            "https://www.sberbank.ru/ru/person",
            "https://github.com/login",
            "https://en.wikipedia.org/wiki/Machine_learning",
            "https://stackoverflow.com/questions",
            "https://www.apple.com/iphone",
            "https://vk.com",
            "https://habr.com/ru/all/"
        ]

        for url in phishing_urls:
            data.append(extract_features(url))
            labels.append(1) 

        for url in legit_urls:
            data.append(extract_features(url))
            labels.append(0)

    if len(data) == 0:
        st.error("❌ Нет данных для обучения!")
        return None

    X = np.array(data)
    y = np.array(labels)

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)
    train_score = clf.score(X, y)
    
    return clf, train_score, len(data)

@st.cache_resource
def load_model():
    model_path = 'phishing_model.pkl'
    
    if os.path.exists(model_path):
        try:
            model = joblib.load(model_path)
            st.success("✅ Загружена предобученная модель")
            return model, 0.95, 1437096
        except Exception as e:
            st.warning(f"⚠️ Не удалось загрузить сохраненную модель: {e}")
            st.info("💡 Запустите train_model.py для обучения модели на всех датасетах")
    
    # Если сохраненной модели нет, используем встроенный датасет для демонстрации
    st.warning("⚠️ Предобученная модель не найдена. Используется демонстрационный датасет.")
    st.info("💡 Для обучения на полном датасете (~1.4M записей) запустите: python3 train_model.py")
    try:
        model, train_accuracy, dataset_size = load_and_train_model(use_csv=False)
        return model, train_accuracy, dataset_size
    except Exception as e:
        st.error(f"Critical System Error: {e}")
        st.stop()

try:
    model, train_accuracy, dataset_size = load_model()
except Exception as e:
    st.error(f"Critical System Error: {e}")
    st.stop()

with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=100)
    st.title("CyberShield v1.0")
    st.markdown("---")
    st.markdown("**Технологии:**")
    st.code("RandomForest\nScikit-learn\nHeuristic Analysis", language="text")
    st.markdown("---")
    
    # Статистика модели
    try:
        st.metric("📊 Размер датасета", f"{dataset_size:,} URL")
        st.metric("🎯 Точность модели", f"{train_accuracy:.1%}")
        st.markdown("---")
        st.markdown("**📦 Источники данных:**")
        st.markdown("• malicious_phish.csv (~651K)")
        st.markdown("• phishing_site_urls.csv (~549K)")
        st.markdown("• PhiUSIIL_Phishing_URL_Dataset.csv (~236K)")
        st.markdown("• legitimate_dataset.csv (~736)")
        st.markdown("• dataset_example.csv (~11)")
        st.markdown(f"• **Всего: ~1,437,000 URL**")
    except:
        pass
    
    st.markdown("---")
    st.info("ℹ️ Этот инструмент анализирует структуру URL, энтропию домена и наличие SSL сертификатов для выявления угроз.")
    st.markdown("**📈 Модель обучена на:**")
    st.markdown("• ~1.4 миллиона URL из 5 датасетов")
    st.markdown("• Легитимные: benign, good, label=0")
    st.markdown("• Фишинговые: phishing, malware, defacement, bad, label=1")
    st.markdown("• 15 признаков: UsingIP, LongURL, ShortURL, HTTPS, Entropy, Hyphens и др.")

col_main, col_padding = st.columns([3, 1])

with col_main:
    st.title("🛡️ Phishing Threat Hunter")
    st.markdown("#### Интеллектуальная система анализа веб-ресурсов")
    
    url_input = st.text_input("Вставьте подозрительную ссылку:", placeholder="example.com/login", help="Введите URL с http/https или без них")

    if st.button("🚀 ЗАПУСТИТЬ СКАНИРОВАНИЕ", type="primary", use_container_width=True):
        if url_input:
            with st.status("🔍 Сканирование ресурса...", expanded=True) as status:
                # Шаг 0: Проверка известного домена (до проверки доступности)
                parsed_input = urlparse(url_input if re.match(r'^https?://', url_input, re.IGNORECASE) else f"http://{url_input}")
                hostname_input = parsed_input.netloc if parsed_input.netloc else url_input.split('/')[0]
                
                # Проверяем, является ли домен известным легитимным
                is_known_domain = is_known_legitimate_domain(hostname_input)
                
                # Шаг 1: Проверка существования сайта
                st.write("🌐 Проверка доступности ресурса...")
                
                # Подготавливаем URL для проверки
                test_url = url_input
                if not re.match(r'^https?://', url_input, re.IGNORECASE):
                    test_url = f"https://{url_input}"
                
                # Проверяем доступность сайта (для известных доменов - более мягкая проверка)
                is_available, error_msg, status_code = check_site_availability(test_url, timeout=5, is_known_domain=is_known_domain)
                
                if not is_available:
                    # Если HTTPS недоступен, пробуем HTTP
                    if 'https://' in test_url:
                        http_url = test_url.replace('https://', 'http://')
                        is_available_http, error_msg_http, status_code_http = check_site_availability(http_url, timeout=5, is_known_domain=is_known_domain)
                        if is_available_http:
                            is_available = True
                            error_msg = error_msg_http
                            status_code = status_code_http
                            test_url = http_url
                    
                    if not is_available:
                        status.update(label="Сканирование завершено", state="error", expanded=False)
                        st.divider()
                        st.markdown(f"""
                        <div class="result-card warning">
                            <h2>⚠️ Ресурс недоступен</h2>
                            <h3 style="font-size: 2em; margin: 20px 0;">САЙТ НЕ СУЩЕСТВУЕТ</h3>
                            <p style="font-size: 1.2em; font-weight: bold; color: #f1c40f;">{error_msg}</p>
                            <p style="margin-top: 15px;">🔍 Возможные причины:</p>
                            <ul style="text-align: left; margin: 15px 0;">
                                <li>Домен не зарегистрирован или удален</li>
                                <li>Сайт временно недоступен</li>
                                <li>Ошибка DNS (домен не существует)</li>
                                <li>Сервер не отвечает</li>
                            </ul>
                            <p style="margin-top: 15px;">⚠️ <strong>Рекомендация:</strong> Не переходите по этой ссылке.</p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        # Показываем вектор признаков для информации
                        with st.expander("🔬 Вектор признаков (для недоступного сайта)"):
                            try:
                                features_vec = np.array(extract_features(test_url)).reshape(1, -1)
                                feature_names = [
                                    'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//', 
                                    'PrefixSuffix-', 'SubDomains', 'HTTPS', 'DomainRegLen', 
                                    'NonStdPort', 'AbnormalURL', 'Entropy', 'SuspiciousWords', 
                                    'KnownDomain', 'Hyphens'
                                ]
                                df = pd.DataFrame(features_vec, columns=feature_names)
                                st.dataframe(df.T, use_container_width=True)
                            except:
                                st.write("Не удалось извлечь признаки")
                        
                        st.stop()
                
                st.write(f"✅ Сайт доступен (статус: {status_code if status_code else 'OK'})")
                final_url = test_url
                
                # Шаг 1: Проверка соединения
                st.write("📡 Установка соединения с хостом...")
                
                if not re.match(r'^https?://', url_input, re.IGNORECASE):
                    # Сначала пробуем HTTPS
                    https_works = False
                    try:
                        test_url = f"https://{url_input}"
                        response = requests.head(test_url, timeout=5, allow_redirects=True, verify=True)
                        # Проверяем, что финальный URL действительно HTTPS
                        if response.url.startswith('https://'):
                            final_url = test_url
                            status_code = response.status_code
                            https_works = True
                            st.write(f"✅ HTTPS Handshake: OK (Code {status_code})")
                    except requests.exceptions.SSLError:
                        # SSL ошибка - точно нет HTTPS
                        final_url = f"http://{url_input}"
                        st.write("⚠️ SSL ошибка. Используется HTTP.")
                    except requests.exceptions.ConnectionError:
                        # Ошибка соединения - пробуем HTTP
                        try:
                            http_url = f"http://{url_input}"
                            http_response = requests.head(http_url, timeout=5, allow_redirects=True)
                            final_url = http_url
                            status_code = http_response.status_code
                            st.write(f"⚠️ HTTPS недоступен. HTTP работает (Code {status_code})")
                        except:
                            final_url = f"http://{url_input}"  # Fallback
                            st.write("⚠️ Не удалось проверить соединение. Предполагается HTTP.")
                    except requests.RequestException:
                        # Другие ошибки - пробуем HTTP
                        try:
                            http_url = f"http://{url_input}"
                            http_response = requests.head(http_url, timeout=5, allow_redirects=True)
                            final_url = http_url
                            status_code = http_response.status_code
                            st.write(f"⚠️ HTTPS недоступен. HTTP работает (Code {status_code})")
                        except:
                            final_url = f"http://{url_input}"  # Fallback
                            st.write("⚠️ Не удалось проверить соединение. Предполагается HTTP.")
                    except Exception:
                        # Любая другая ошибка
                        final_url = f"http://{url_input}"
                        st.write("⚠️ Ошибка проверки. Предполагается HTTP.")
                else:
                    final_url = url_input
                    st.write(f"ℹ️ Используется протокол из запроса: {final_url.split(':')[0]}")

                st.write("🧠 Анализ векторов атаки (RandomForest)...")
                features_vec = np.array(extract_features(final_url)).reshape(1, -1)
                probability = model.predict_proba(features_vec)[0][1]
                
                status.update(label="Сканирование завершено", state="complete", expanded=False)

            # --- РЕЗУЛЬТАТЫ ---
            st.divider()
            
            # Отображение через HTML/CSS карточки
            if probability > 0.7:
                st.markdown(f"""
                <div class="result-card danger">
                    <h2>🚨 Обнаружена фишинговая атака</h2>
                    <h3 style="font-size: 2.5em; margin: 20px 0;">УГРОЗА ОБНАРУЖЕНА</h3>
                    <p style="font-size: 1.3em; font-weight: bold;">Уровень опасности: {probability:.0%}</p>
                    <p style="margin-top: 15px;">⚠️ Данный ресурс классифицирован как мошеннический.</p>
                    <p>Рекомендуется немедленно прекратить взаимодействие с сайтом.</p>
                </div>
                """, unsafe_allow_html=True)
            elif probability > 0.4:
                st.markdown(f"""
                <div class="result-card suspicious">
                    <h2>⚠️ Подозрительная активность</h2>
                    <h3 style="font-size: 2.5em; margin: 20px 0;">ТРЕБУЕТ ВНИМАНИЯ</h3>
                    <p style="font-size: 1.3em; font-weight: bold;">Уровень риска: {probability:.0%}</p>
                    <p style="margin-top: 15px;">Обнаружены некоторые признаки, указывающие на возможную угрозу.</p>
                    <p>Рекомендуется дополнительная проверка перед использованием ресурса.</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="result-card safe">
                    <h2>✅ Ресурс безопасен</h2>
                    <h3 style="font-size: 2.5em; margin: 20px 0;">БЕЗОПАСНО</h3>
                    <p style="font-size: 1.3em; font-weight: bold;">Уровень угрозы: {probability:.0%}</p>
                    <p style="margin-top: 15px;">✓ Признаков фишинга не обнаружено.</p>
                    <p>Ресурс соответствует критериям безопасности.</p>
                </div>
                """, unsafe_allow_html=True)

            # Технические детали
            st.markdown("### 🔬 Вектор признаков")
            df = pd.DataFrame(features_vec, columns=[
                "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//", 
                "PrefixSuffix-", "SubDomains", "HTTPS", "DomainRegLen", 
                "NonStdPort", "AbnormalURL", "Entropy", "SuspiciousWords", 
                "KnownDomain", "Hyphens"
            ])
            st.dataframe(df, hide_index=True, use_container_width=True)

        else:
            st.warning("Введите URL для начала работы.")
