# zadanie 1 - weryfikacja wycieku wrażliwych danych

W logach aplikacji Java można wykryć podatność polegająca na wycieku wrażliwych danych tj. adres zamieszkania dodanego użytkownika. 
![](./logs1.png)

Żeby zabezpieczyć się przed podatnością nie zmieniając formatu logów, można zamaksować wrażliwe dane znakami "*" jak na screenie niżej.
![](./masked.png)

Maskowanie osiągnięto modyfikując metodę toString w klasie Address: \
![](./maskfield.png)

# Zadanie 2 - weryfikacja wycieku sekretów

Wykonano skan programem gitleaks w poszukiwaniu sekretów, które mogły zostać zahardcodowane w kodzie źródłowym i wypchnięte do repozytorium. Wynik skanu:
<pre>

    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

Finding:     -----BEGIN RSA PRIVATE KEY-----                                 
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUp...                                                          
Secret:      -----BEGIN RSA PRIVATE KEY-----                                 
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUp...                                                          
RuleID:      private-key
Entropy:     5.875154
File:        deployment.key
Line:        1
Commit:      bc17b7ddc46f46fff175aed55d68e11bb48166cc
Author:      Grzegorz Siewruk
Email:       gsiewruk@gmail.com
Date:        2023-11-15T12:52:32Z
Fingerprint: bc17b7ddc46f46fff175aed55d68e11bb48166cc:deployment.key:private-key:1

Finding:     -----BEGIN RSA PRIVATE KEY-----                                 
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUp...                                                          
Secret:      -----BEGIN RSA PRIVATE KEY-----                                 
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUp...                                                          
RuleID:      private-key
Entropy:     5.875154
File:        deployment2.key
Line:        1
Commit:      de9d7b8cb63bd7ae741ec5c9e23891b71709bc28
Author:      Grzegorz Siewruk
Email:       gsiewruk@gmail.com
Date:        2023-11-15T12:49:39Z
Fingerprint: de9d7b8cb63bd7ae741ec5c9e23891b71709bc28:deployment2.key:private-key:1

Finding:     "private_key_id": "002ac3c1623rdewc7bb13f6b10e6"
Secret:      002ac3c1623rdewc7bb13f6b10e6
RuleID:      generic-api-key
Entropy:     3.645593
File:        awscredentials.json
Line:        4
Commit:      bc17b7ddc46f46fff175aed55d68e11bb48166cc
Author:      Grzegorz Siewruk
Email:       gsiewruk@gmail.com
Date:        2023-11-15T12:52:32Z
Fingerprint: bc17b7ddc46f46fff175aed55d68e11bb48166cc:awscredentials.json:generic-api-key:4

Finding:     "private_key": "-----BEGIN PRIVATE KEY-----\nlRsGbRO/1A5LiQHjuR5SASDASDAiSMNeOYqna2R+HEalBoyISASDASD1Tgkj\n4CC02Uux+...\n",
Secret:      -----BEGIN PRIVATE KEY-----\nlRsGbRO/1A5LiQHjuR5SASDASDAiSMNeOYqna2R+HEalBoyISASDASD1Tgkj\n4CC02Uux+...
RuleID:      private-key
Entropy:     5.917361
File:        awscredentials.json
Line:        5
Commit:      bc17b7ddc46f46fff175aed55d68e11bb48166cc
Author:      Grzegorz Siewruk
Email:       gsiewruk@gmail.com
Date:        2023-11-15T12:52:32Z
Fingerprint: bc17b7ddc46f46fff175aed55d68e11bb48166cc:awscredentials.json:private-key:5

5:27AM INF 6 commits scanned.
5:27AM INF scan completed in 40.5s
5:27AM WRN leaks found: 4
</pre>

Wyniki skanu są poprawne - wycieki zostały poprwanie oznaczone. Porgram nie zasygnalizował wykrycia fałszywie pozytywnego.

# Zadanie 3 - weryfikacja bezpieczeństwa bibliotek OS wykorzystywanych w projekcie

Żeby zweryfikować dependencje aplikacji Python, uruchomiony został program safety:
<pre>
+==============================================================================+
|                                                                              |
|                               /$$$$$$            /$$                         |
|                              /$$__  $$          | $$                         |
|           /$$$$$$$  /$$$$$$ | $$  \__//$$$$$$  /$$$$$$   /$$   /$$           |
|          /$$_____/ |____  $$| $$$$   /$$__  $$|_  $$_/  | $$  | $$           |
|         |  $$$$$$   /$$$$$$$| $$_/  | $$$$$$$$  | $$    | $$  | $$           |
|          \____  $$ /$$__  $$| $$    | $$_____/  | $$ /$$| $$  | $$           |
|          /$$$$$$$/|  $$$$$$$| $$    |  $$$$$$$  |  $$$$/|  $$$$$$$           |
|         |_______/  \_______/|__/     \_______/   \___/   \____  $$           |
|                                                          /$$  | $$           |
|                                                         |  $$$$$$/           |
|  by pyup.io                                              \______/            |
|                                                                              |
+==============================================================================+
| REPORT                                                                       |
| checked 18 packages, using free DB (updated once a month)                    |
+============================+===========+==========================+==========+
| package                    | installed | affected                 | ID       |
+============================+===========+==========================+==========+
| jinja2                     | 3.1.2     | <3.1.3                   | 64227    |
+==============================================================================+
| Jinja2 before 3.1.3 is affected by a Cross-Site Scripting vulnerability.     |
| Special placeholders in the template allow writing code similar to Python    |
| syntax. It is possible to inject arbitrary HTML attributes into the rendered |
| HTML template. The Jinja 'xmlattr' filter can be abused to inject arbitrary  |
| HTML attribute keys and values, bypassing the auto escaping mechanism and    |
| potentially leading to XSS. It may also be possible to bypass attribute      |
| validation checks if they are blacklist-based.                               |
+==============================================================================+
| jinja2                     | 3.1.2     | <3.1.4                   | 71591    |
+==============================================================================+
| Jinja is an extensible templating engine. The `xmlattr` filter in affected   |
| versions of Jinja accepts keys containing non-attribute characters. XML/HTML |
| attributes cannot contain spaces, `/`, `>`, or `=`, as each would then be    |
| interpreted as starting a separate attribute. If an application accepts keys |
| (as opposed to only values) as user input, and renders these in pages that   |
| other users see as well, an attacker could use this to inject other          |
| attributes and perform XSS. The fix for CVE-2024-22195 only addressed spaces |
| but not other characters. Accepting keys as user input is now explicitly     |
| considered an unintended use case of the `xmlattr` filter, and code that     |
| does so without otherwise validating the input should be flagged as          |
| insecure, regardless of Jinja version. Accepting _values_ as user input      |
| continues to be safe.                                                        |
+==============================================================================+
| jinja2                     | 3.1.2     | >=0                      | 70612    |
+==============================================================================+
| In Jinja2, the from_string function is prone to Server Side Template         |
| Injection (SSTI) where it takes the source parameter as a template object,   |
| renders it, and then returns it. The attacker can exploit it with INJECTION  |
| COMMANDS in a URI.                                                           |
| NOTE: The maintainer and multiple third parties believe that this            |
| vulnerability isn't valid because users shouldn't use untrusted templates    |
| without sandboxing.                                                          |
+==============================================================================+
| werkzeug                   | 2.3.7     | <2.3.8                   | 62019    |
+==============================================================================+
| Werkzeug 3.0.1 and 2.3.8 include a security fix: Slow multipart parsing for  |
| large parts potentially enabling DoS attacks.                                |
| https://github.com/pallets/werkzeug/commit/b1916c0c083e0be1c9d887ee2f3d69692 |
| 2bfc5c1                                                                      |
+==============================================================================+
| werkzeug                   | 2.3.7     | <3.0.3                   | 71594    |
+==============================================================================+
| Werkzeug is a comprehensive WSGI web application library. The debugger in    |
| affected versions of Werkzeug can allow an attacker to execute code on a     |
| developer's machine under some circumstances. This requires the attacker to  |
| get the developer to interact with a domain and subdomain they control, and  |
| enter the debugger PIN, but if they are successful it allows access to the   |
| debugger even if it is only running on localhost. This also requires the     |
| attacker to guess a URL in the developer's application that will trigger the |
| debugger.                                                                    |
+==============================================================================+
| werkzeug                   | 2.3.7     | <3.0.6                   | 73969    |
+==============================================================================+
| Affected versions of Werkzeug are vulnerable to Path Traversal (CWE-22) on   |
| Windows systems running Python versions below 3.11. The safe_join() function |
| failed to properly detect certain absolute paths on Windows, allowing        |
| attackers to potentially access files outside the intended directory. An     |
| attacker could craft special paths starting with "/" that bypass the         |
| directory restrictions on Windows systems. The vulnerability exists in the   |
| safe_join() function which relied solely on os.path.isabs() for path         |
| validation. This is exploitable on Windows systems by passing paths starting |
| with "/" to safe_join(). To remediate, upgrade to the latest version which   |
| includes additional path validation checks.                                  |
| NOTE: This vulnerability specifically affects Windows systems running Python |
| versions below 3.11 where ntpath.isabs() behavior differs.                   |
+==============================================================================+
| werkzeug                   | 2.3.7     | <3.0.6                   | 73889    |
+==============================================================================+
| Affected versions of Werkzeug are vulnerable to possible resource exhaustion |
| when parsing file data in forms.                                             |
+==============================================================================+
| werkzeug                   | 2.3.7     | <=2.3.7                  | 71595    |
+==============================================================================+
| Werkzeug is a comprehensive WSGI web application library. If an upload of a  |
| file that starts with CR or LF and then is followed by megabytes of data     |
| without these characters: all of these bytes are appended chunk by chunk     |
| into internal bytearray and lookup for boundary is performed on growing      |
| buffer. This allows an attacker to cause a denial of service by sending      |
| crafted multipart data to an endpoint that will parse it. The amount of CPU  |
| time required can block worker processes from handling legitimate requests.  |
+==============================================================================+
| healpy                     | 1.8.0     | <=1.16.6                 | 61774    |
+==============================================================================+
| Healpy 1.16.6 and prior releases ship with a version of 'libcurl' that has a |
| high-severity vulnerability.                                                 |
+==============================================================================+
</pre>


Wyniki zawierają informację o dependencjach analizowanej aplikacji, tj:
- który pakiet, oraz w jakiej wersji jest podany
- opis podatności

Zostało wykryte 9 podatności, w tym dosyć świeżą (25.10.2024) podatność w pakiecie werkzeug (<3.0.6). Podatność pozwala na wykonanie ataku typu <b>Path Traversal ([CWE-22](https://cwe.mitre.org/data/definitions/22.html))</b> w aplikacji uruchomionej na serwerze Windowsowym z Pythonem w wersji < 3.11.

Funkcja `safe_join()` odpowiedzialna za podatność, weryfikuje, czy podana ścieżka pozostaje w granicach zaufanego katalogu. Opiera się ona na `os.path.isabs()` do stwierdzenia czy ścieżka jest absolutna, co umożliwia obejście walidacji dla ścieżek zaczynających się od `/` na serwerach Windowsowych. W takim przypadku atakujący wkorzystując róznice w interpretacji ścieżek na systemach Windows, jest w stanie uzyskać dostęp do plików spoza aplikacji (np. do plików konfiguracyjnych, sekretów, .env, itp).

Pomimo że w kodzie naszej aolikacji funkcja `wekrzeug.safe_join()` nie została bezpośrednio użyta, nie możemy lekceważyć tej podatności. Biblioteka `werkzeug` jest kluczowym komponentem Flaska, więc jej wykonanie może nie być dla nas widoczne i zależy od użytej wersji flaska. 

Podatność zarejestrowana jako [CVE-2024-49766](https://nvd.nist.gov/vuln/detail/CVE-2024-49766):
- NVD assessment not yet provided
- CVSS-B: 6.3 MEDIUM
- published 10/25/2024