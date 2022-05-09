from website import create_app

app = create_app()
#app3 = create_app3()

if __name__ == '__main__':
    app.run(debug=True)
    #app3.run(debug=True)