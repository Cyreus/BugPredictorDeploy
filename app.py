from flask import Flask, render_template, request, redirect
import os
import pandas as pd
import joblib
import ast
from collections import defaultdict
import requests
from urllib.parse import urlparse
import chardet
import nbformat
import gc

app = Flask(__name__)

UPLOAD_FOLDER = './uploads'

DOWNLOAD_FOLDER = './downloads'

app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

if not os.path.exists(DOWNLOAD_FOLDER):
    os.makedirs(DOWNLOAD_FOLDER)

ALLOWED_EXTENSIONS = {'py', 'ipynb'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


model = joblib.load('./saved_models/mk1plus.pkl')

scaler = joblib.load('./scaler/scaler.pkl')


class CodeAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.metrics = {
            "cbo": 0,  # Coupling Between Objects
            "dit": 0,  # Depth of Inheritance Tree
            "fanIn": defaultdict(int),
            "fanOut": defaultdict(int),
            "lcom": 0,  # Lack of Cohesion of Methods
            "noc": 0,  # Number of Children
            "numberOfAttributes": 0,
            "numberOfAttributesInherited": 0,
            "numberOfLinesOfCode": 0,
            "numberOfMethods": 0,
            "numberOfMethodsInherited": 0,
            "numberOfPrivateAttributes": 0,
            "numberOfPrivateMethods": 0,
            "numberOfPublicAttributes": 0,
            "numberOfPublicMethods": 0,
            "rfc": 0,  # Response for Class
            "wmc": 0,  # Weighted Methods per Class
        }
        self.current_class = None
        self.current_methods = []
        self.attribute_access = defaultdict(set)
        self.inheritance_map = {}
        self.method_calls = defaultdict(set)

    def visit_ClassDef(self, node):
        self.current_class = node.name
        self.metrics["noc"] += 1
        self.inheritance_map[node.name] = [base.id for base in node.bases if isinstance(base, ast.Name)]
        self.generic_visit(node)
        self.current_class = None

    def visit_FunctionDef(self, node):
        if self.current_class:
            self.current_methods.append(node.name)
            if node.name.startswith("__"):
                self.metrics["numberOfPrivateMethods"] += 1
            else:
                self.metrics["numberOfPublicMethods"] += 1
            self.metrics["numberOfMethods"] += 1

            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Call) and isinstance(stmt.func, ast.Attribute):
                    self.method_calls[node.name].add(stmt.func.attr)

        self.generic_visit(node)

        if self.current_methods:
            self.current_methods.pop()

    def visit_Assign(self, node):
        if isinstance(node.targets[0], ast.Attribute) and isinstance(node.targets[0].value, ast.Name):
            if self.current_class:
                attr_name = node.targets[0].attr
                if attr_name.startswith("_"):
                    self.metrics["numberOfPrivateAttributes"] += 1
                else:
                    self.metrics["numberOfPublicAttributes"] += 1
                self.metrics["numberOfAttributes"] += 1
        self.generic_visit(node)

    def visit_Attribute(self, node):
        if self.current_methods:
            self.attribute_access[self.current_methods[-1]].add(node.attr)
        self.generic_visit(node)

    def visit_Module(self, node):
        self.metrics["numberOfLinesOfCode"] = len(node.body)
        self.generic_visit(node)

    def calculate_metrics(self):
        external_classes = set()
        for calls in self.method_calls.values():
            external_classes.update(calls)
        self.metrics["cbo"] = len(external_classes)

        self.metrics["dit"] = self._calculate_dit()

        # FanIn and FanOut
        for method, calls in self.method_calls.items():
            self.metrics["fanOut"][method] = len(calls)
            for call in calls:
                self.metrics["fanIn"][call] += 1

        self.metrics["lcom"] = self._calculate_lcom()

        self.metrics["rfc"] = self.metrics["numberOfMethods"] + sum(len(calls) for calls in self.method_calls.values())

        self.metrics["wmc"] = self.metrics["numberOfMethods"]

    def _calculate_dit(self):
        def get_depth(cls):
            if cls not in self.inheritance_map or not self.inheritance_map[cls]:
                return 0
            return 1 + max(get_depth(base) for base in self.inheritance_map[cls])

        return max((get_depth(cls) for cls in self.inheritance_map), default=0)

    def _calculate_lcom(self):
        total_pairs = len(self.attribute_access) * (len(self.attribute_access) - 1) / 2
        if total_pairs == 0:
            return 0
        shared_attributes = sum(
            len(self.attribute_access[m1] & self.attribute_access[m2])
            for i, m1 in enumerate(self.attribute_access)
            for m2 in list(self.attribute_access)[i + 1:]
        )
        return 1 - (shared_attributes / total_pairs)

    def analyze(self, code):
        tree = ast.parse(code)
        self.visit(tree)
        self.calculate_metrics()

    def get_metrics(self):
        return self.metrics


def extract_code_from_ipynb(file_path, encoding):
    try:
        with open(file_path, 'r', encoding=encoding) as f:
            nb = nbformat.read(f, as_version=4)
        code_cells = [cell['source'] for cell in nb.cells if cell['cell_type'] == 'code']
        return '\n\n'.join(code_cells)
    except Exception as e:
        return f"ipynb file reading error: {str(e)}"


def extract_metrics_from_file(file_path):
    try:
        rawdata = open(file_path, 'rb').read()
        result = chardet.detect(rawdata)
        encoding = result['encoding']

        extension = file_path.rsplit('.', 1)[1].lower()
        if extension == 'ipynb':
            code = extract_code_from_ipynb(file_path, encoding)
            if isinstance(code, str) and code.startswith("ipynb reading file error!"):
                return code
        else:
            with open(file_path, "r", encoding=encoding) as f:
                code = f.read()

    except (UnicodeDecodeError, Exception) as e:
        print(f"file reading error!: {e}")
        return None

    analyzer = CodeAnalyzer()

    try:
        analyzer.analyze(code)  # Analyze the code
    except IndentationError as e:
        return f"There is an indentation error in your code. Please check it. Error: {str(e)}"
    except SyntaxError as e:
        return f"There is a syntax error in your code. Please check it. Error: {str(e)}"
    except Exception as e:
        return f"An unknown error occurred. Please check your code. Error: {str(e)}"
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)
            gc.collect()

    metrics_dict = analyzer.get_metrics()

    metrics_dict["fanIn"] = sum(metrics_dict["fanIn"].values()) if isinstance(metrics_dict["fanIn"], defaultdict) else \
        metrics_dict["fanIn"]
    metrics_dict["fanOut"] = sum(
        len(v) if hasattr(v, "__len__") else 1 for v in metrics_dict["fanOut"].values()) if isinstance(
        metrics_dict["fanOut"], defaultdict) else metrics_dict["fanOut"]

    return pd.DataFrame([metrics_dict])


def download_github_file(github_url, download_folder="downloads"):
    if github_url.startswith("https://github.com"):
        raw_url = github_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")

        parsed_url = urlparse(github_url)
        file_name = os.path.basename(parsed_url.path)

        os.makedirs(download_folder, exist_ok=True)

        file_path = os.path.join(download_folder, file_name)

        response = requests.get(raw_url)
        if response.status_code == 200:
            with open(file_path, 'wb') as file:
                file.write(response.content)
            print(f"File downloaded successfully: {file_path}")
            return file_path
        else:
            print(f"Failed to download the file. HTTP Status Code: {response.status_code}")
            return None
    else:
        print("Invalid GitHub URL provided.")
        return None


# Ana sayfa
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/upload')
def upload():
    return render_template('upload.html')


@app.route('/predict', methods=['POST'])
def predict():
    if 'file' in request.files and request.files['file'].filename != '':
        file = request.files['file']

        if not allowed_file(file.filename):
            return render_template('upload.html', error="You can upload just python file!")

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        input_data = extract_metrics_from_file(file_path)
        if isinstance(input_data, str):
            return render_template('upload.html', error=input_data)

    elif 'github_url' in request.form and request.form['github_url'] != '':
        github_url = request.form['github_url']
        file_path = download_github_file(github_url)
        if not file_path:
            return render_template('upload.html', error="invalid github link!")
        input_data = extract_metrics_from_file(file_path)

        if isinstance(input_data, str):
            return render_template('upload.html', error=input_data)

    else:
        return redirect(request.url)

    if file_path and os.path.exists(file_path):
        os.remove(file_path)
        gc.collect()

    scaled_data = scaler.transform(input_data)
    prediction = model.predict(scaled_data)
    result = int(prediction[0])
    nolc = input_data['numberOfLinesOfCode'].iloc[0]
    noc = input_data['noc'].iloc[0]
    cbo = input_data['cbo'].iloc[0]
    dit = input_data['dit'].iloc[0]
    noa = input_data['numberOfAttributes'].iloc[0]
    lcom = input_data['lcom'].iloc[0]
    nom = input_data['numberOfMethods'].iloc[0]
    rfc = input_data['rfc'].iloc[0]
    wmc = input_data['wmc'].iloc[0]
    fanIn = input_data['fanIn'].iloc[0]
    fanOut = input_data['fanOut'].iloc[0]

    return render_template('index.html', result=result, noc=noc, cbo=cbo, dit=dit, noa=noa, lcom=lcom, nom=nom,
                           rfc=rfc, wmc=wmc, fanIn=fanIn, fanOut=fanOut, nolc=nolc)


if __name__ == '__main__':
    app.run(debug=True)
