const container = document.getElementById('container');
const registerBtn = document.getElementById('register');
const loginBtn = document.getElementById('login');
const signUpForm = document.getElementById('signUpForm');
const loginForm = document.getElementById("loginForm") 
const messageBox = document.querySelector(".message")

// console.log(container,registerBtn,loginBtn,signUpForm,messageBox);

registerBtn.addEventListener('click', (e) => {
    container.classList.add("active");
});

loginBtn.addEventListener('click', () => {
    container.classList.remove("active");
});

signUpForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = document.getElementById("username-sign-up").value;
    const email = document.getElementById("email-sign-up").value;
    const password = document.getElementById("password-sign-up").value;

    try{
        const res = await fetch("http://127.0.0.1:8000/main/user/signup/",{
            method:"POST",
            headers:{
                "Content-Type":"application/json"
            },
            body:JSON.stringify(
                {username,email,password}
            )
        })

        const data = await res.json();
        messageBox.style.display = "block";

        if (data.username || data.email || data.password){
            messageBox.textContent = data.username || data.email || data.password;
        }
    }

    catch (err){
        console.log("Error in Sign up Function",err);
        
    }

});

loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const email = document.getElementById("email-sign-in").value;
    const password = document.getElementById("password-sign-in").value;

    try{
        const res = await fetch("http://127.0.0.1:8000/main/user/login/",{
            method:"POST",
            headers:{
                "Content-Type":"application/json"
            },
            body:JSON.stringify(
                {email,password}
            )
        })

        const data = await res.json();
        messageBox.style.display = "block";

        if (data.error){
            messageBox.textContent = data.error;
        }
        else{
            messageBox.textContent = data.message;
            localStorage.setItem("access",data.access)
            window.location.href = "index.html"
        }
        
    }

    catch (err){
        console.log("Error in Sign up Function",err);
        
    }

});