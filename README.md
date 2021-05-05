A Simple Example of Terraform 
===========

A simple example of Terraform inspired by `Yuki Nomura. Jissen Terraform. September 20, 2019 (ISBN-10: 4844378139)`.


Usage
-----
 Acquires a domain and create Route 53 zone in AWS management console beforehand, execute below command.
```
$ terraform apply -var 'domain_name=example.com'
```
