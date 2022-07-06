**Final project by Group 8**
```
  A python Flask webapp that is made to take CSV files and turn them into charts using chart.js
```  
**Implemented**
```
  1) Login, Logout, Signup system
    > Hashed passwords
    > Input validation
  2) User database
    > First name
    > last name
    > email
    > (hashed) password
    > admin status
    > date created
    > last login (updates at each login) 
  3) User can input file to create a graph in the dahsboard
    > Form with file upload and graph type, redirects to a new page with the chart made
    > Data from the file in translated into json
    > Chart is inaccurate at the moment
  4) Profile tab to change personal content
  5) Admin tab accessiable only if you are an admin
    > Will show database of users and allow an admin to ban or unban non admin users
```
**Next steps**
```
  Better chart validation and input
```
**How to run** 
```
  1) Download the folder and install required libraries
  2) In a python terminal
    >> from main import db
    >> db.create_all()
    >> exit()
  3) Check if the database is created after step 1 in the terminal
    $ sqlite 3 database.db
    $ .tables
      user     <------ Correct output
    $ .exit
  4) Run program
  5) Go to [Local Host](http://localhost:5000/)
```
