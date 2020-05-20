.. PartnerHTC Backend documentation master file, created by
   sphinx-quickstart on Thu May  7 09:57:43 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Configuration of Project Environment
*************************************

This is an API that manages Mini Mofa system using Python3, Flask, and SQLAlchemy.

Overview on How to Run this API
================================
1. Install Windows Server 2012 R2
2. Install Miniconda 3.7
3. Install packages required in requirements.txt
4. Install MySQL 5.7, Redis

General API Information
=========================
1. The base endpoint is: http://27.72.196.104:5012
2. The backup endpoint is: http://27.72.196.105:5012
3. All endpoints return a JSON object.
4. All time and timestamp related fields are in seconds.

HTTP Return Codes
=====================
1. 2xx Request processed successfully
2. 5xx return codes are used for internal errors; the issue is on Backend side.

Setup Environment
=================

1. Configure project environment (Either A. Install Pycharm OR B. Create a Virtual Environment)

    A. Install Environment
    - Manually install packages to project interpreter (Pycharm -> Preferences -> Project -> Project Interpreter -> plus button on the lower left side of the package table) and apply changes OR type the command below on the activated virtual environment. ::

        conda activate
        conda create -n htcenv python=3.6
        conda activate htcenv
        pip install -r requirements.txt

2. Install MySQL, REDIS Database

    A. Search on the web on how to install MySQL in your OS

    B. Create database through piping ::

        mysql -u root < <Path to file>/create_db.sql
        * NOTE: depending on your mysql config, you need to provide your password if you have one

    C. Download and install redis via this link

    D. Restart Computer

3. Initialize and Populate Database

    A. Edit line 14 of settings.py and use the correct url to your mysql. ::

        'mysql://root:<password>@localhost/htc'

    B. Either run the line below. ::

        $ sh database_populator.sh

4. Run application::

    python manage.py

5. Refer to controller on how to test the code through curl or Postman

Documentation for the Code
**************************
.. toctree::
   :maxdepth: 2
   :caption: Contents:

Authentication Services
========================
.. automodule:: app.api.v1.auth
   :members:

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
