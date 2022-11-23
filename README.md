<a name="Gozscaler"></a>
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]



<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/zepryspet/gozscaler">
    <img src="images/logo.jpeg" alt="Logo" width="300" height="80">
  </a>

  <p align="center">
    SDK for zscaler public APIs for ZIA, ZPA and ZCC
    <br />
    <a href="https://pkg.go.dev/github.com/zepryspet/gozscaler"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/zepryspet/gozscaler/issues">Report Bug</a>
    ·
    <a href="https://github.com/zepryspet/gozscaler/issues">Request Feature</a>
  </p>
</div>



<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project


Gozscaler is an sdk for zscaler public apis built purely in go and without 3rd party dependencies.

[![go][go.com]][go-url]

## Pre-requierements
* [Go version 1.18+]([go-url]) since go generics are used


ZPA sdk

* [Client secret and client api.](https://help.zscaler.com/zpa/zpa-api/api-developer-reference-guide) 
* Cloud name. options:
    * config.private.zscaler.com
    * config.zpabeta.net

ZIA sdk
* Administrator, password
* [Api key](https://help.zscaler.com/zia/getting-started-zia-api)
* Cloud name. options:
    * zscaler
    * zscloud
    * zscalerbeta
    * zscalerone
    * zscalertwo
    * zscalerthree

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- GETTING STARTED -->
## Getting Started




_Below is an example of how you can instruct your audience on installing and setting up your app. This template doesn't rely on any external dependencies or services._

1. Get a free API Key at [https://example.com](https://example.com)
2. Clone the repo
   ```sh
   git clone https://github.com/your_username_/Project-Name.git
   ```
3. Install NPM packages
   ```sh
   npm install
   ```
4. Enter your API in `config.js`
   ```js
   const API_KEY = 'ENTER YOUR API';
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- USAGE EXAMPLES -->
## Examples

Use this space to show useful examples of how a project can be used. Additional screenshots, code examples and demos work well in this space. You may also link to more resources.

_For more examples, please refer to the [Documentation](https://example.com)_

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- ROADMAP -->
## Roadmap

- [x] Add Changelog
- [x] Add back to top links
- [ ] Add Additional Templates w/ Examples
- [ ] Add "components" document to easily copy & paste sections of the readme
- [ ] Multi-language Support
    - [ ] Chinese
    - [ ] Spanish

See the [open issues](https://github.com/zepryspet/gozscaler/issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- CONTACT -->
## Contact

Your Name - [@your_twitter](https://twitter.com/your_username) - email@example.com

Project Link: [https://github.com/your_username/repo_name](https://github.com/your_username/repo_name)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

Use this space to list resources you find helpful and would like to give credit to. I've included a few of my favorites to kick things off!

* [Choose an Open Source License](https://choosealicense.com)
* [GitHub Emoji Cheat Sheet](https://www.webpagefx.com/tools/emoji-cheat-sheet)
* [Malven's Flexbox Cheatsheet](https://flexbox.malven.co/)
* [Malven's Grid Cheatsheet](https://grid.malven.co/)
* [Img Shields](https://shields.io)
* [GitHub Pages](https://pages.github.com)
* [Font Awesome](https://fontawesome.com)
* [React Icons](https://react-icons.github.io/react-icons/search)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/zepryspet/gozscaler?style=for-the-badge
[contributors-url]: https://github.com/zepryspet/gozscaler/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/zepryspet/gozscaler?style=for-the-badge
[forks-url]: https://github.com/epryspet/gozscaler/network/members
[stars-shield]: https://img.shields.io/github/stars/zepryspet/gozscaler?style=for-the-badge
[stars-url]: https://github.com/zepryspet/gozscaler/stargazers
[issues-shield]: https://img.shields.io/github/issues/zepryspet/gozscaler?style=for-the-badge
[issues-url]: https://github.com/zepryspet/gozscaler/issues
[license-shield]: https://img.shields.io/github/license/zepryspet/gozscaler?style=for-the-badge
[license-url]: https://github.com/zepryspet/gozscaler/blob/master/LICENSE.md
[go.com]: https://img.shields.io/badge/go-white?style=for-the-badge&logo=go
[go-url]: https://go.dev/dl/