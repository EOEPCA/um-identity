<!--
***
*** To avoid retyping too much info. Do a search and replace for the following:
*** um-identity-service
-->

<!-- PROJECT SHIELDS -->
<!--
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
![Build][build-shield]

<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/EOEPCA/um-identity-service">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">Identity service</h3>

  <p align="center">
    Identity service for EOEPCA project
</p>

## Table of Contents

- [About the Project](#about-the-project)
  - [Built With](#built-with)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Testing](#testing)
- [Documentation](#documentation)
- [Usage](#usage)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)
- [Acknowledgements](#acknowledgements)

### About The Project

Identity offers seemingly authentication and authorization to be added to Applications.  
Includes five main components:
- **Keycloak integration**: Open Source Identity and Access Management.
- **Identity Manager**: Web application using AngularJS and Angular Material to visually interact with the platform. Interacts with Identity API.
- **Identity API**: API using Flask Framework to be consumed by Identity Manager. Interacts with Keycloak API.
- **OAuth2 Proxy integration**: Authentication Proxy to enable seemless authentication and authorization to be added to Applications. Interacts with Keycloak.
- **PostgreSQL**: SQL database for Keycloak to store data.

### Built With

- [Keycloak](https://www.keycloak.org/)
- [AngularJS](https://angularjs.org/) + [Angular Material](https://material.angular.io/)
- [Flask Framework](https://flask.palletsprojects.com/en/2.3.x/)
- [OAuth2 Proxy](https://oauth2-proxy.github.io/oauth2-proxy/)
- [PostgreSQL](https://www.postgresql.org/)

## Getting Started

Using Docker compose:

```shell
docker-compose up -d
```

Using Helm:

```shell
helm install identity infra
```

### Prerequisites

- [Docker](https://www.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)  
or
- [Helm](https://helm.sh/)
- [Kubernetes](https://kubernetes.io/)  
- [Rancher](https://www.rancher.com/) (Optional)

### Installation

1. Get into EOEPCA's development environment

```shell
vagrant ssh
```

2. Clone the repo

```shell
git clone https://github.com/EOEPCA/um-identity-service.git
```

3. Change local directory

```shell
cd um-identity-service
```

## Documentation

The component documentation can be found at https://eoepca.github.io/um-identity-service/.

<!-- USAGE EXAMPLES -->

## Usage

- **Docker-compose:**  
`Identity-manager` >>>>> http://localhost:4200   
`Identity-api` >>>>> http://localhost:8081  
`Keycloak` >>>>> http://localhost:8080  
`OAuth2 Proxy` >>>>> http://localhost:4180  


- **Helm charts:**  
`Identity-manager` >>>>> https://identity.manager.local.eoepca.org  
`Identity-api` >>>>> https://identity.api.local.eoepca.org  
`Keycloak` >>>>> https://identity.keycloak.local.eoepca.org  
`OAuth2 Proxy` >>>>> https://identity.proxy.local.eoepca.org  

## Roadmap

See the [open issues](https://github.com/EOEPCA/um-identity-service/issues) for a list of proposed features (and known issues).

<!-- CONTRIBUTING -->

## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<!-- LICENSE -->

## License

Distributed under the Apache-2.0 License. See `LICENSE` for more information.

## Contact

[EOEPCA mailbox](eoepca.systemteam@telespazio.com)

Project Link: [https://github.com/EOEPCA/um-identity-service](https://github.com/EOEPCA/um-identity-service)

## Acknowledgements

- README.md is based on [this template](https://github.com/othneildrew/Best-README-Template) by [Othneil Drew](https://github.com/othneildrew).


[contributors-shield]: https://img.shields.io/github/contributors/EOEPCA/um-identity-service.svg?style=flat-square
[contributors-url]: https://github.com/EOEPCA/um-identity-service/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/EOEPCA/um-identity-service.svg?style=flat-square
[forks-url]: https://github.com/EOEPCA/um-identity-service/network/members
[stars-shield]: https://img.shields.io/github/stars/EOEPCA/um-identity-service.svg?style=flat-square
[stars-url]: https://github.com/EOEPCA/um-identity-service/stargazers
[issues-shield]: https://img.shields.io/github/issues/EOEPCA/um-identity-service.svg?style=flat-square
[issues-url]: https://github.com/EOEPCA/um-identity-service/issues
[license-shield]: https://img.shields.io/github/license/EOEPCA/um-identity-service.svg?style=flat-square
[license-url]: https://github.com/EOEPCA/um-identity-service/blob/master/LICENSE
[build-shield]: https://www.travis-ci.com/EOEPCA/um-identity-service.svg?branch=master
