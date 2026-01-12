import ipaddress
import re
import socket
import urllib.request
from datetime import date
from urllib.parse import urlparse

import numpy as np
import pickle
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, render_template
from googlesearch import search
import whois


# ================= FEATURE EXTRACTION ================= #

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.domain = ""
        self.features = []

        try:
            self.response = requests.get(url, timeout=5)
            self.soup = BeautifulSoup(self.response.text, "html.parser")
        except:
            self.response = None
            self.soup = None

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            self.urlparse = None

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            self.whois_response = None

        self.features = [
            self.using_ip(),
            self.url_length(),
            self.short_url(),
            self.symbol(),
            self.redirecting(),
            self.prefix_suffix(),
            self.sub_domains(),
            self.https_token(),
            self.domain_age(),
        ]

    def using_ip(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    def url_length(self):
        length = len(self.url)
        if length < 54:
            return 1
        elif 54 <= length <= 75:
            return 0
        return -1

    def short_url(self):
        shortening_services = r"bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co"
        return -1 if re.search(shortening_services, self.url) else 1

    def symbol(self):
        return -1 if "@" in self.url else 1

    def redirecting(self):
        return -1 if self.url.count("//") > 1 else 1

    def prefix_suffix(self):
        return -1 if "-" in self.domain else 1

    def sub_domains(self):
        dots = self.domain.count(".")
        if dots == 1:
            return 1
        elif dots == 2:
            return 0
        return -1

    def https_token(self):
        return 1 if self.urlparse and self.urlparse.scheme == "https" else -1

    def domain_age(self):
        try:
            creation_date = self.whois_response.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            age = (date.today() - creation_date.date()).days
            return 1 if age > 180 else -1
        except:
            return -1

    def get_features(self):
        return np.array(self.features).reshape(1, -1)


# ================= FLASK APP ================= #

app = Flask(__name__)

# Load trained model
with open("model.pkl", "rb") as f:
    model = pickle.load(f)


@app.route("/", methods=["GET", "POST"])
def index():
    prediction = None
    confidence = None

    if request.method == "POST":
        url = request.form.get("url")
        features = FeatureExtraction(url).get_features()

        pred = model.predict(features)[0]
        prob = model.predict_proba(features)

        prediction = "Safe Website" if pred == 1 else "Phishing Website"
        confidence = round(max(prob[0]) * 100, 2)

    return render_template(
        "index.html",
        prediction=prediction,
        confidence=confidence,
    )


if __name__ == "__main__":
    app.run(debug=True)
