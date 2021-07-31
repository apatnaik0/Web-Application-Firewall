# Web Application Firewall

## What is a Web Application Firewall?

A Web Application Firewall (WAF) protects your web apps by filtering, monitoring, and blocking any malicious HTTP/S traffic traveling to the web application, and prevents any unauthorized data from leaving the app. It does this by adhering to a set of policies that help determine what traffic is malicious and what traffic is safe. Just as a proxy server acts as an intermediary to protect the identity of a client, a WAF operates in similar fashion but in the reverse—called a reverse proxy—acting as an intermediary that protects the web app server from a potentially malicious client.

WAFs can come in the form of software, an appliance, or delivered as-a-service. Policies can be customized to meet the unique needs of your web application or set of web applications. Although many WAFs require you update the policies regularly to address new vulnerabilities, advances in machine learning enable some WAFs to update automatically. This automation is becoming more critical as the threat landscape continues to grow in complexity and ambiguity.

In this work we investigate the use of machine learning techniques to leverage the performance of Web Application Firewalls (WAFs), systems that are used to detect and prevent attacks. 

## Use of ML Techniques in Web Attack Detection

The traditional IDS cannot detect and restrict the attacks in full scale as they are limited to observe static patterns in the web requests, when the malicious web request is slightly encoded and passed it can easily traverse through the IDS and cause damage. Here I have used flow based traffic characteristics to analyze the difference in pattern between normal vs anomaly packet. We evaluate several supervised classification algorithms using metrics like maximum detection accuracy, lowest false negatives prediction. ML Algorithms are capable of learning large amount of malicious and benign requests of different patterns and can predict them effectively in production.

Here I have used several supervised ML algorithms and computed few performance metrics. I have also plotted ROC, PR and Confusion matrix plots so that the required conclusions can be drawn.

## OWASP Top 10

The OWASP Top 10 is a standard awareness document for developers and web application security. It represents a broad consensus about the most critical security risks to web applications.

Companies should adopt this document and start the process of ensuring that their web applications minimize these risks. Using the OWASP Top 10 is perhaps the most effective first step towards changing the software development culture within your organization into one that produces more secure code.

The OWASP Top 10 Web Attacks Are:-

**A1:2017-Injection:** Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query. The attacker’s hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.

**A2:2017-Broken Authentication:** Application functions related to authentication and session management are often implemented incorrectly, allowing attackers to compromise passwords, keys, or session tokens, or to exploit other implementation flaws to assume other users’ identities temporarily or permanently.

**A3:2017-Sensitive Data Exposure:** Many web applications and APIs do not properly protect sensitive data, such as financial, healthcare, and PII. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes. Sensitive data may be compromised without extra protection, such as encryption at rest or in transit, and requires special precautions when exchanged with the browser.

**A4:2017-XML External Entities (XXE):** Many older or poorly configured XML processors evaluate external entity references within XML documents. External entities can be used to disclose internal files using the file URI handler, internal file shares, internal port scanning, remote code execution, and denial of service attacks.

**A5:2017-Broken Access Control:** Restrictions on what authenticated users are allowed to do are often not properly enforced. Attackers can exploit these flaws to access unauthorized functionality and/or data, such as access other users’ accounts, view sensitive files, modify other users’ data, change access rights, etc.

**A6:2017-Security Misconfiguration:** Security misconfiguration is the most commonly seen issue. This is commonly a result of insecure default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages containing sensitive information. Not only must all operating systems, frameworks, libraries, and applications be securely configured, but they must be patched/upgraded in a timely fashion.

**A7:2017-Cross-Site Scripting XSS:** XSS flaws occur whenever an application includes untrusted data in a new web page without proper validation or escaping, or updates an existing web page with user-supplied data using a browser API that can create HTML or JavaScript. XSS allows attackers to execute scripts in the victim’s browser which can hijack user sessions, deface web sites, or redirect the user to malicious sites.

**A8:2017-Insecure Deserialization:** Insecure deserialization often leads to remote code execution. Even if deserialization flaws do not result in remote code execution, they can be used to perform attacks, including replay attacks, injection attacks, and privilege escalation attacks.

**A9:2017-Using Components with Known Vulnerabilities:** Components, such as libraries, frameworks, and other software modules, run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover. Applications and APIs using components with known vulnerabilities may undermine application defenses and enable various attacks and impacts.

**A10:2017-Insufficient Logging & Monitoring:** Insufficient logging and monitoring, coupled with missing or ineffective integration with incident response, allows attackers to further attack systems, maintain persistence, pivot to more systems, and tamper, extract, or destroy data. Most breach studies show time to detect a breach is over 200 days, typically detected by external parties rather than internal processes or monitoring.

## The Dataset

The dataset used to implement this WAF consists of Web Access Logs, proving information about various web requests made across the server and whether they are malicious or not. Unfortunately I will not be able to share the dataset used publicly. Since I have implemented this WAF during my internship under a company using their dataset, company policy does not allow me to share the dataset publicly. It makes sense to do so as sharing the data used to train any such firewall would make it easier for cyber attackers to get across the firewall.

My dataset consisting of 22,801 requests was split into Training Data and Test Data.
The training set and test set consist of 18,240 and 4,561 requests respectively.
Overall the dataset has 14,390 non-malicious and 8,411 malicious requests.

## Data Preprocessing and Handling

I have used a Machine Learning Pipeline for each model, to handle all the features. A machine learning pipeline is a way to codify and automate the workflow it takes to produce a machine learning model. Machine learning pipelines consist of multiple sequential steps that do everything from data extraction and preprocessing to model training and deployment.

The pipeline helps me split the features into numerical data, text data and categorical data and deal with each of them accordingly. For the text data, I have used a Count Vectorizer which transforms the text into a vector containing the frequency of each character provided it crosses a minimum frequency. For the numeric data, the numeric data is fed to the model as it is as no changes are required. For the categorical data, I have used a Dict Vectorizer which converts the categorical features into numpy arrays indicating the selected category with a 1 and the others with a 0. This make sit easier for the ML Model to analyse the various features better and provide us with more accurate results.

After this the data preprocessing is complete and now the data can be fed into the model. The model to be used for training is also listed within the pipeline. This means the data can now be fit and trained. Once the training is complete, the test set is fed into the model and key metrics are calculated.

## Models Used

1.	Stochastic Gradient Descent (SGD) Classifier
2.	Logistic Regression Classifier
3.	Support Vector Machine (SVM) Classifier
4.	K Nearest Neighbours (KNN) Classifier
5.	Decision Tree Classifier
6.	Random Forest Classifier
7.	XGB Classifier

## Metrics Used

**Average Precision:** It is the Area Under the Precision-Recall Curve.
**Accuracy:** Accuracy is the most intuitive performance measure and it is simply a ratio of correctly predicted observation to the total observations.
**Precision:** Precision is the ratio of correctly predicted positive observations to the total predicted positive observations
**ROC Curve:** An ROC curve (receiver operating characteristic curve) is a graph showing the performance of a classification model at all classification thresholds. This curve plots two parameters: True Positive Rate. False Positive Rate.
**Confusion Matrix:** A confusion matrix is a table that is often used to describe the performance of a classification model (or "classifier") on a set of test data for which the true values are known.

## Conclusion

From the models that I have tested on, I can conclude that 'Random Forest Classifier' and 'XGB Classifier' have the Highest True Positive rate, Lowest False Positive Rate and Highest Area Under the Curve (AOC). Hence, this indicates that these 2 Models provide us with the Best Results for our Dataset.
