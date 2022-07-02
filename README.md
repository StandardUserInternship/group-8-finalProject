Final project by Group 8 -
  A python Flask webapp thatis made to take CSV files and turn them into charts using chart.js
  
Implemented -
  Login, Logout, Signup system
    > Hashed passwords
    > Input validation
  User database
    > First name, last name, email, (hashed) password, admin status, date created, last login (updates at each login) 
  User can input file to create a graph in the dahsboard
    > Form with file upload and graph type, redirects to a new page with the chart made
    > Data from the file in translated into json
    > Chart is inaccurate at the moment
  Profile tab to change personal content
    > Profile information wont change at the moment
  Admin tab accessiable only if you are an admin
    > Will show database of users and allow an admin to ban or unban users (ban/unban unimplemented at the moment)

Next steps - 
  Profile page input will chnage data on the database
  Better chart validation and input
  Implement the admin ban / unban buttons

How to run - 
  Download the folder and install required libraries
  1) In a python terminal
    >> from main import db
    >> db.create_all()
    >> exit()
  2) Check if the database is created after step 1 in the terminal
    $ sqlite 3 database.db
    $ .tables
      user     <------ Correct output
    $ .exit
