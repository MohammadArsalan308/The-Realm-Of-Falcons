from flask import Flask, render_template , request,redirect,flash,make_response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from time import sleep
import json
from flask import session
from utilities.port_scan import bcolors
from utilities.bruteforcing import bruteforcings
from utilities.Subdomains import subdomains
from vulnerability_check.xss_check import scan_xss
from vulnerability_check.sqli_check import scan_sql_injection
from utilities.links_extractor import crawl
from vulnerability_check.vuln_solution import remediation , remediation_for_xss,remediation_for_sql

import nmap
import re  		    # To ensure that the input is correctly formatted.
import threading
import socket
from threading import Thread
import os
from werkzeug.utils import secure_filename
import pdfkit
path_wkthmltopdf = b'C:\Program Files\wkhtmltopdf\\bin\wkhtmltopdf.exe'
config = pdfkit.configuration(wkhtmltopdf=path_wkthmltopdf)

port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
print_lock = threading.Lock() 
nm = nmap.PortScanner()
thread_list = []
labels = ['Critical', 'High', 'Medium', 'Low', 'Info']
values = []
colors = ['#FF0000', '#FFA500', '#FFFF00', '#008000', '#0000FF']

with open('Config.json', 'r') as c:
    params = json.load(c)["params"]

local_server = True

app = Flask(__name__)

app.secret_key = 'super-secret-key'
app.config['UPLOAD_FOLDER'] = params['upload_location']

if(local_server):
    app.config['SQLALCHEMY_DATABASE_URI'] = params['local_uri']
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = params['prod_uri']

db = SQLAlchemy(app)
# check the connection of internet
def isConnect():
	try:
		s = socket.create_connection(
			("www.geeksforgeeks.org", 80))
		if s is not None:
			s.close
		return True
	except OSError:
		pass
	return False


class User(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    img_file = db.Column(db.String(12), nullable=True)
    create_data = db.Column(db.String(12), nullable=True)

class Scan_details(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    Description = db.Column(db.String(250), nullable=False)
    port_range = db.Column(db.String(100), nullable=False)
    Target = db.Column(db.String(250), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    create_date = db.Column(db.String(12), nullable=True)

class Attack_details(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    Description = db.Column(db.String(250), nullable=False)
    target = db.Column(db.String(250), nullable=False)
    attack_type = db.Column(db.String(50), nullable=False)
    create_date = db.Column(db.String(12), nullable=True)


class MyView:
    def __init__(self):
        self.scan_data_list = []  # Initialize an empty list

    def add_data(self, item):
        self.scan_data_list.append(item)
    
    def clear_data(self):
        self.scan_data_list.clear()

    def get_data(self):
        return self.scan_data_list

class bruteforcing:
    def __init__(self):
        self.bruteforcing_list = []  # Initialize an empty list

    def add_data(self, item):
        self.bruteforcing_list = item
    
    def clear_data(self):
        self.bruteforcing_list.clear()

    def get_data(self):
        return self.bruteforcing_list
    
class subdomain:
    def __init__(self):
        self.subdomain_list = []  # Initialize an empty list

    def add_data(self, item):
        self.subdomain_list = item
    
    def clear_data(self):
        self.subdomain_list.clear()

    def get_data(self):
        return self.subdomain_list
    
class xss_data:
    def __init__(self):
        self.xss_data_list = []  # Initialize an empty list

    def add_data(self, item):
        self.xss_data_list.append(item)
    
    def clear_data(self):
        self.xss_data_list.clear()

    def get_data(self):
        return self.xss_data_list

class sql_data:
    def __init__(self):
        self.sql_data_list = []  # Initialize an empty list

    def add_data(self, item):
        self.sql_data_list.append(item)
    
    def clear_data(self):
        self.sql_data_list.clear()

    def get_data(self):
        return self.sql_data_list

class report_xss_data:
    def __init__(self):
        self.xss_data_list = []  # Initialize an empty list

    def add_data(self, item):
        self.xss_data_list.append(item)
    
    def clear_data(self):
        self.xss_data_list.clear()

    def get_data(self):
        return self.xss_data_list

class report_sql_data:
    def __init__(self):
        self.sql_data_list = []  # Initialize an empty list

    def add_data(self, item):
        self.sql_data_list.append(item)
    
    def clear_data(self):
        self.sql_data_list.clear()

    def get_data(self):
        return self.sql_data_list

class MyView_solution:
    def __init__(self):
        self.port_solution = []  # Initialize an empty list

    def add_data(self, item):
        self.port_solution.append(item)
    
    def clear_data(self):
        self.port_solution.clear()

    def get_data(self):
        return self.port_solution

class subdomain_solution:
    def __init__(self):
        self.subdomain_solution_list = []  # Initialize an empty list

    def add_data(self, item):
        self.subdomain_solution_list.append(item)
    
    def clear_data(self):
        self.subdomain_solution_list.clear()

    def get_data(self):
        return self.subdomain_solution_list

class bruteforcing_solution:
    def __init__(self):
        self.bruteforcing_solution_list = []  # Initialize an empty list

    def add_data(self, item):
        self.bruteforcing_solution_list.append(item)
    
    def clear_data(self):
        self.bruteforcing_solution_list.clear()

    def get_data(self):
        return self.bruteforcing_solution_list
    
class xss_solution:
    def __init__(self):
        self.xss_solution = []  # Initialize an empty list

    def add_data(self, item):
        self.xss_solution.append(item)
    
    def clear_data(self):
        self.xss_solution.clear()

    def get_data(self):
        return self.xss_solution
    
class sql_solution:
    def __init__(self):
        self.sql_solution = []  # Initialize an empty list

    def add_data(self, item):
        self.sql_solution.append(item)
    
    def clear_data(self):
        self.sql_solution.clear()

    def get_data(self):
        return self.sql_solution
    
class chart_data:
    def __init__(self):
        self.chart_data_list = []  # Initialize an empty list

    def add_data(self, item):
        self.chart_data_list.append(item)
    
    def clear_data(self):
        self.chart_data_list.clear()

    def get_data(self):
        return self.chart_data_list

view = MyView()  # Create an instance of MyView
view1 = subdomain()  # Create an instance of MyView
view2 = bruteforcing()  # Create an instance of MyView
view3 = xss_data()  # Create an instance of MyView
view4 = sql_data()  # Create an instance of MyView
view5 = MyView_solution()  # Create an instance of MyView
view6 = xss_solution()  # Create an instance of MyView
view7 = chart_data()  # Create an instance of MyView
view8 = subdomain_solution()  # Create an instance of MyView
view9 = bruteforcing_solution()  # Create an instance of MyView
view10 = sql_solution()  # Create an instance of MyView
view11 = report_xss_data()  # Create an instance of MyView
view12 = report_sql_data()  # Create an instance of MyView

@app.route("/",methods=['GET', 'POST'])
def Login():
    if "user_email" in session:
        scan_all =Scan_details.query.filter_by().all()
        user = User.query.filter_by(email=session['user_email']).first()
        return render_template("index.html", params=params ,scan_all=scan_all,user=user)
    
    if request.method=='POST':
        print("Post")
        email = request.form.get('email')
        password = request.form.get('pswd')
        print(email+password)
        session['user_email'] = email
        scan_all =Scan_details.query.filter_by().all()
        login = User.query.filter_by(email=email, password=password).first()
        if login is not None:
            user = User.query.filter_by(email=session['user_email']).first()
            return render_template('index.html',params=params,scan_all=scan_all,user=user)
        else:
            flash("Please enter correct email or password")
        return render_template('login.html',params=params,email=email,password=password)
    return render_template('login.html',params=params)


@app.route("/Signup",methods=['GET', 'POST'])
def Signups():
    if request.method=='POST':
        print("Post")
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('pswd')
        print(name+email+password)
        emt = User.query.filter_by(email=email).first()
        if emt is not None:
            flash("Email is already exists!!!")
        else:
            entry =User(name= name,email=email,password=password, img_file="avatar.png",create_data= datetime.now())
            db.session.add(entry)
            db.session.commit()
            flash("Sign up Successfully!!!")
    return render_template('login.html',params=params)


@app.route("/EditUser",methods=['GET', 'POST'])
def EditUser():
    if "user_email" in session:
        if request.method=='POST':
            print("Post")
            name = request.form.get('name')
            # email = request.form.get('email')
            f = request.files['img']
            password = request.form.get('pswd')
            print(name+password+" ")
            edit_user = User.query.filter_by(email=session['user_email']).first()
            edit_user.name = name
            edit_user.password = password
            if str(f.filename)!='':
                f.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(f.filename)))
                edit_user. img_file = str(f.filename)
            edit_user.create_date= datetime.now()
            db.session.commit()
            flash("Profile Edit Successfully!!!")
            return redirect('/index')
    return render_template('login.html',params=params)


@app.route('/logout')
def logout():
    session.pop('user_email')
    return redirect('/')

@app.route("/index",methods=['GET', 'POST'])
def index():
    if "user_email" in session:
        scan_all = Scan_details.query.filter_by().all()
        user = User.query.filter_by(email=session['user_email']).first()
        return render_template("index.html", params=params,scan_all=scan_all,user=user)
    return render_template('login.html',params=params)

@app.route("/basic_scan",methods=['GET', 'POST'])
def base_scan():
    if "user_email" in session:
        if request.method=='POST':
            print("Post")
            name = request.form.get('name')
            dist = request.form.get('dist')
            minport = request.form.get('minport')
            maxport = request.form.get('maxport')
            minbox = request.form.get('minbox')
            maxbox = request.form.get('maxbox')
            target = request.form.get('target')
            scan_type ="Basic Port"
            if(maxbox != "" and minbox !=""):
                minport=minbox
                maxport=maxbox
            port_range=minport+"-"+maxport
            print(name+dist+target+minport+maxport)
            emt = Scan_details.query.filter_by(name=name).first()
            if emt is not None:
                flash("Name is already exists!!!")
            elif int(minport)>= int(maxport):
                print(port_range)
                flash("Enter the correct port range!!!")
            else:
                entry =Scan_details(name= name,Description=dist,port_range=port_range,Target=target,scan_type=scan_type,create_date= datetime.now())
                db.session.add(entry)
                db.session.commit()
                if request.form['action'] == 'save':
                    flash("Basic Scan Saved Successfully!!!")
                    return redirect("/")
                elif request.form['action'] == 'start_scan':
                    flash("Basic Scan Completed!!!")
                    emt1 = Scan_details.query.filter_by(name=name).first()
                    return redirect("/basic_scan_start/"+str(emt1.sno))
        user = User.query.filter_by(email=session['user_email']).first()
        return redirect('/index')
    return render_template('login.html',params=params)

@app.route("/advanced_scan",methods=['GET', 'POST'])
def advanced_scan():
    if "user_email" in session:
        if request.method=='POST':
            print("Post")
            name = request.form.get('name')
            dist = request.form.get('dist')
            minport = request.form.get('minport')
            maxport = request.form.get('maxport')
            minbox = request.form.get('minbox')
            maxbox = request.form.get('maxbox')
            target = request.form.get('target')
            if(maxbox != "" and minbox !=""):
                minport=minbox
                maxport=maxbox
            port_range=minport+"-"+maxport
            print(name+dist+target+minport+maxport)
            emt = Scan_details.query.filter_by(name=name).first()
            if emt is not None:
                flash("Name is already exists!!!")
            elif int(minport)>= int(maxport):
                print(port_range)
                flash("Enter the correct port range!!!")
            else:
                entry =Scan_details(name= name,Description=dist,port_range=port_range,Target=target,scan_type="Advanced Port",create_date= datetime.now())
                db.session.add(entry)
                db.session.commit()
                if request.form['action'] == 'save':
                    flash("Advanced Scan Saved Successfully!!!")
                    return redirect("/")
                elif request.form['action'] == 'start_scan':
                    flash("Advanced Scan Completed!!!")
                    emt1 = Scan_details.query.filter_by(name=name).first()
                    return redirect("/basic_scan_start/"+str(emt1.sno))
        user = User.query.filter_by(email=session['user_email']).first()
        return redirect('/index')
    return render_template('login.html',params=params)

@app.route("/Web_Application_Tests",methods=['GET', 'POST'])
def Web_Application_Tests():
    if "user_email" in session:
        if request.method=='POST':
            print("Post")
            name = request.form.get('name')
            dist = request.form.get('dist')
            target = request.form.get('target')
            scan_type ="Web Application Tests"
            port_range="None"
            print(name+dist+target)
            emt = Scan_details.query.filter_by(name=name).first()
            if emt is not None:
                flash("Name is already exists!!!")
            else:
                entry =Scan_details(name= name,Description=dist,port_range=port_range,Target=target,scan_type=scan_type,create_date= datetime.now())
                db.session.add(entry)
                db.session.commit()
                if request.form['action'] == 'save':
                    flash("Web Application Tests Save Successfullyly!!!")
                    return redirect("/")
                elif request.form['action'] == 'start_scan':
                    emt1 = Scan_details.query.filter_by(name=name).first()
                    return redirect("/basic_scan_start/"+str(emt1.sno))
        user = User.query.filter_by(email=session['user_email']).first()
        return redirect('/index')
    return render_template('login.html',params=params)


@app.route("/basic_scan_update/<string:sno>",methods=['GET', 'POST'])
def basic_scan_update(sno):
    if "user_email" in session:
        if request.method=='POST':
            print("Post")
            name = request.form.get('name')
            dist = request.form.get('dist')
            ports = request.form.get('port_range')
            target = request.form.get('target')
            if ports!="None":
                minport,maxport = ports.split('-')
                port_range=minport+"-"+maxport
            else:
                port_range=ports
            
            if ports!="None" and int(minport)>= int(maxport):
                flash("Enter the correct port range!!!")
            elif ports:
                print(name+dist+target+ports)
                scan_all = Scan_details.query.filter_by(sno=sno).first()
                scan_all.name = name
                scan_all.Description = dist
                scan_all.port_range = port_range
                scan_all.Target = target
                scan_all.create_date= datetime.now()
                db.session.commit()
                flash("Updated Successfully!!!")
                return redirect('/index')
        print(sno)
        return redirect('/')
    return render_template('login.html',params=params)
    

@app.route("/basic_scan_delete/<string:sno>" , methods=['GET', 'POST'])
def basic_scan_delete(sno):
    if "user_email" in session:
        scan_all = Scan_details.query.filter_by(sno=sno).first()
        db.session.delete(scan_all)
        db.session.commit()
        a=scan_all.name + " Deleted Successfully!!!"
        flash(a)
    return redirect("/")
    
@app.route("/scan",methods=['GET', 'POST'])
def about(sno):
    if "user_email" in session:
        #if request.method=='POST':
        print("Post")
        scan_all = Scan_details.query.filter_by(sno=sno).first()
        target = scan_all.Target
        port_range = scan_all.port_range 
#            return render_template('basic_scan_start.html',params=params)
    return render_template('login.html',params=params)


@app.route('/basic_scan_start/<string:sno>', methods=['POST','GET'])
def scan(sno):
    if "user_email" in session:
        scan_all = Scan_details.query.filter_by(sno=sno).first()
        target = scan_all.Target
        port_range = scan_all.port_range
        scan_type =scan_all.scan_type 
        print(target,port_range,scan_type)
        
        def nmapScan(port):
            result = nm.scan(target, str(port))
            
            for host in nm.all_hosts():						# nm.all_hosts() = ['10.10.10.10']
                for proto in nm[host].all_protocols():      # nm[host].all_protocols() = tcp
                    pass

            service = (result['scan'][host][proto][port]['name'])
            service_product = (result['scan'][host][proto][port]['product'])
            service_version = (result['scan'][host][proto][port]['version'])
            service_os = (result['scan'][host][proto][port]['extrainfo'])
            print(f"{bcolors.GREEN}[*]{bcolors.RESET} Port {port}/{proto}: {bcolors.GREEN}open{bcolors.RESET}" + f"\tService: {bcolors.GREEN}{service}{bcolors.RESET}" + f"\tVersion: {bcolors.GREEN}{service_product} {service_version}{bcolors.RESET}" + f"\tOS: {bcolors.GREEN}{service_os} {bcolors.RESET}")
            view.add_data({'port': port, 'protocol': proto, 'service': service, 'version': service_product+service_version, 'os_family': service_os})
        
            sleep(0.1)

        def portScan(port):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                connection = s.connect((target, port))
                with print_lock:
                    nmapScan(port)
                connection.close()
            except:
                pass

        def port_scan_start(target,port_range):
            port_range_fixer = port_range_pattern.search(port_range.replace(" ",""))

            if port_range_fixer:
                port_min = int(port_range_fixer.group(1))
                port_max = int(port_range_fixer.group(2))

            start_time = datetime.now()
            print(f"\nStarting {bcolors.CYAN}Full Scan{bcolors.RESET} for {bcolors.ORANGE}{target}{bcolors.RESET} at {bcolors.ORANGE}{start_time}{bcolors.RESET}")

            threads = []
            for ip in range(port_min, port_max + 1):
                thread = Thread(target=portScan, args=(ip,))
                thread.start()
                threads.append(thread)

            for thread in threads:
                thread.join()
            end_time = datetime.now()
            print(f"Ending {bcolors.CYAN}Full Scan{bcolors.RESET} for {bcolors.ORANGE}{target}{bcolors.RESET} at {bcolors.ORANGE}{end_time}{bcolors.RESET}")
            total_time = end_time - start_time
            print(f"\nTotal Time Elasped: {bcolors.CYAN}{total_time}{bcolors.RESET}")
        
        view.clear_data()
        view1.clear_data()
        view2.clear_data()
        view3.clear_data()
        view4.clear_data()
        view5.clear_data()
        view6.clear_data()
        view7.clear_data()
        view8.clear_data()
        view9.clear_data()
        view10.clear_data()
        view11.clear_data()
        view12.clear_data()
        data=[]
        # xss_solution=[]
        # chart_data_list=[]
        data.clear()
        # chart_data_list.clear()
        # xss_solution.clear()

        if isConnect():
            try:
                if scan_type == "Basic Port":
                    port_scan_start(target,port_range)

                    if 0<len(view.get_data()):
                        are,b,c=remediation(3, 1, 2)
                        view5.add_data(are)   
                        view5.add_data(b)   
                        view5.add_data(c)
                        view7.add_data(are.split(" ")[1].upper())


                elif scan_type == "Web Application Tests":
                    BASE_TARGET = f"http://{target}"
                    print(f"\nStarting {bcolors.CYAN}Web Crawler{bcolors.RESET} on {bcolors.ORANGE}{target}{bcolors.RESET}")
                    print("==========",BASE_TARGET)
                    data=crawl(BASE_TARGET)
                    print(data)
                    count=0
                    pre_count=0
                    print(f"\nInitiating {bcolors.CYAN}Cross-Site Scripting Attacks/Vulnerabilty Check{bcolors.RESET} on {bcolors.ORANGE}{target}{bcolors.RESET}")
                    # with open(f"{target}_internal_links.txt") as fp1:
                    for line in data:
                        data_list,a=scan_xss(line)
                        count+=a
                        view3.add_data(data_list)
                        if count >pre_count:
                            view11.add_data(data_list)
                            pre_count=count
                        print("Count =",count)
                        print("###################################################################")

                    if count >= 1:
                        are,b,c=remediation(0, 1, 2)
                        view6.add_data(are)   
                        view6.add_data(b)   
                        view6.add_data(c)
                        view7.add_data(are.split(" ")[1].upper())


                    count12=0
                    pre_count12=0   
                    print(f"\nInitiating {bcolors.CYAN}SQL Injection Attacks/Vulnerabilty Check{bcolors.RESET} on {bcolors.ORANGE}{target}{bcolors.RESET}")
                    # with open(f"{target}_internal_links.txt") as fp2:
                    for line in data:
                        _listdata,a=scan_sql_injection(line)
                        count12+=a
                        # if count12 >pre_count12:
                        #     view12.add_data(data_list)
                        #     pre_count12=count12
                        #     print("+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_")
                        view4.add_data(_listdata)
                        print("Count =",count12)
                        print("###################################################################")
                
                    if count12 >= 1:
                            are,b,c=remediation(2, 1, 2)
                            view10.add_data(are)   
                            view10.add_data(b)   
                            view10.add_data(c)
                            view7.add_data(are.split(" ")[1].upper())

                    for inner_list in view4.get_data():
                        for i,element in enumerate(inner_list):
                            print(i,' ',element)
                            if element=="True":
                                view12.add_data(inner_list)
                                # pre_count1=count1
                                print("+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_")
                        print()
                    print("###################################################################")
                    
                    # for inner_list in view4.get_data():
                    #     for i,element in enumerate(inner_list):
                    #         print(i,' ',element)
                    #     print()
                    flash("Web Application Tests Completed")
                else:
                    port_scan_start(target,port_range)
                    #port scan soiution
                    if 0<len(view.get_data()):
                        are,b,c=remediation(3, 1, 2)
                        view5.add_data(are)   
                        view5.add_data(b)   
                        view5.add_data(c)
                        view7.add_data(are.split(" ")[1].upper())
                    

                    print(f"\nStarting {bcolors.CYAN}Directory/File bruteforcing{bcolors.RESET} on {bcolors.ORANGE}{target}{bcolors.RESET}")
                    view1.add_data(bruteforcings(target))
                    for item in view1.get_data():
                        print("Response for",item['url'] , item['response_status_code'])
                    #solution
                    if 0<len(view1.get_data()):
                        are,b,c=remediation(4, 1, 2)
                        view9.add_data(are)   
                        view9.add_data(b)   
                        view9.add_data(c)
                        view7.add_data(are.split(" ")[1].upper())

                    print(f"\nStarting {bcolors.CYAN}Subdomain enumeration{bcolors.RESET} on {bcolors.ORANGE}{target}{bcolors.RESET}")
                    view2.add_data(subdomains(target))
                    for item in view2.get_data():
                        print("[+] Discovered subdomain:",item['subdomain'])
                    #solution
                    if 0<len(view2.get_data()):
                        are,b,c=remediation(5, 1, 2)
                    
                        view8.add_data(are)   
                        view8.add_data(b)   
                        view8.add_data(c)
                        view7.add_data(are.split(" ")[1].upper())

                    BASE_TARGET = f"http://{target}"
                    print(f"\nStarting {bcolors.CYAN}Web Crawler{bcolors.RESET} on {bcolors.ORANGE}{target}{bcolors.RESET}")
                    print("==========",BASE_TARGET)
                    data=crawl(BASE_TARGET)
                    print(data)
                    count=0
                    pre_count=0
                    print(f"\nInitiating {bcolors.CYAN}Cross-Site Scripting Attacks/Vulnerabilty Check{bcolors.RESET} on {bcolors.ORANGE}{target}{bcolors.RESET}")
                    # with open(f"{target}_internal_links.txt") as fp1:
                    for line in data:
                        data_list,a=scan_xss(line)
                        count+=a
                        view3.add_data(data_list)
                        if count >pre_count:
                            view11.add_data(data_list)
                            pre_count=count
                        print("Count =",count)
                        print("###################################################################")

                    if count >= 1:
                        are,b,c=remediation(0, 1, 2)
                        view6.add_data(are)   
                        view6.add_data(b)   
                        view6.add_data(c)
                        view7.add_data(are.split(" ")[1].upper())


                    count1=0
                    print(f"\nInitiating {bcolors.CYAN}SQL Injection Attacks/Vulnerabilty Check{bcolors.RESET} on {bcolors.ORANGE}{target}{bcolors.RESET}")
                    # with open(f"{target}_internal_links.txt") as fp2:
                    for line in data:
                        _listdata,a=scan_sql_injection(line)
                        count1+=a
                        view4.add_data(_listdata)
                        print("Count =",count1)
                        print("###################################################################")
                
                    if count1 >= 1:
                            are,b,c=remediation(2, 1, 2)
                            view10.add_data(are)   
                            view10.add_data(b)   
                            view10.add_data(c)
                            view7.add_data(are.split(" ")[1].upper())

                    for inner_list in view4.get_data():
                        for i,element in enumerate(inner_list):
                            print(i,' ',element)
                            if element=="True":
                                view12.add_data(inner_list)
                                # pre_count1=count1
                                print("+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_")
                        print()
                    print("###################################################################")
               
                # print(chart_data_list)
                values.clear()
                for i in labels:
                    count=0
                    for j in view7.get_data():
                        if j.upper()==i.upper():
                            count+=1
                    values.append(count)
                print(values)
                donet_data = list(zip(labels, values, colors))
                user = User.query.filter_by(email=session['user_email']).first()
                return render_template('basic_scan_start.html',params=params,user=user,scan_all=scan_all, target=target, start_port=port_range, scan_data_list=view.get_data(),bruteforcing_list=view1.get_data(),subdomain_list=view2.get_data(),xss_data_list=view3.get_data(),sql_data_list=view4.get_data(),port_solution=view5.get_data(),xss_solution=view6.get_data(),sql_solution=view10.get_data() ,subdomain_solution_list=view8.get_data(),bruteforcing_solution_list=view9.get_data(),donet_data=donet_data)
            except KeyboardInterrupt:
                print(f"{bcolors.RED}\n[-] Received Ctrl+C hit, Shutting down...{bcolors.RESET}")
                flash("Please check your internet connection !!!!")
                return redirect("/")
                raise SystemExit
            # finally:
            #      return redirect("/")

        else:
            flash("Please check your internet connection !!!")
            return redirect("/")
    return render_template('login.html',params=params)



# @app.route("/about",methods=['GET', 'POST'])
# def abouts():
#     if "user_email" in session:
#         if request.method=='POST':
#             print("Post")
#     return render_template('about.html',params=params)


@app.route('/report/<string:sno>', methods =["GET", "POST"])
def gfg(sno):
    if "user_email" in session:
        scan_all = Scan_details.query.filter_by(sno=sno).first()
        target = scan_all.Target
        port_range = scan_all.port_range
        scan_type =scan_all.scan_type 
        
        print(target,port_range,scan_type)
        user = User.query.filter_by(email=session['user_email']).first()
        html = render_template('report.html', params=params,user=user,scan_all=scan_all, target=target, start_port=port_range, scan_data_list=view.get_data(),bruteforcing_list=view1.get_data(),subdomain_list=view2.get_data(),xss_data_list=view11.get_data(),sql_data_list=view12.get_data(),port_solution=view5.get_data(),subdomain_solution_list=view8.get_data(),bruteforcing_solution_list=view9.get_data(),xss_solution=view6.get_data(),sql_solution=view10.get_data())

        pdf=pdfkit.from_string(html, False, configuration=config)
        response = make_response(pdf)
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = "inline; filename=output.pdf"
        return response
    return render_template('login.html',params=params)
if __name__ == "__main__":
    app.run(debug=True , port=11000)
