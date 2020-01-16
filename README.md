# GeneXus Security API for .NET and .NET Core
These are the source of the GeneXus Security API.

## Modules

| Name  | Description
|---|---
| SecurityAPICommons | Classes common to all GeneXusSecurityAPI modules, output is GeneXusSecurityAPICommonsImpl.dll
| GeneXusCryptography | GeneXus Cryptography Module, output is GeneXusCryptographyImpl.dll
| GeneXusXmlSignature | GeneXus Xml Signature Module, output is GeneXusXmlSignatureImpl.dll
| GeneXusJWT | GeneXus Json Web Token Module, output is GeneXusJWTImpl.dll
| GeneXusSftp | GeneXus SFTP Module, output is GeneXusSftpImpl.dll


# How to compile

## Requirements
Visual Stuio 2019 or dotnet SDK >= 3.1 
- .Net framework 4.6 
- .Net framework 4.7 is required for GeneXus SFTP Module

# Instructions

## How to build all projects?
- ```dotnet build DotNetStandardClasses.sln```


## How to build a specific project?
- ```dotnet build project.csproj```


## License

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
