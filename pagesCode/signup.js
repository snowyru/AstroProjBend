// (1) Create an empty array called registrationForm
let registrationForm = new FormData();

function registerUser() {
  // (2) Use document to get the text elements
  let textElements = document.getElementsByClassName("field");

  let firstNameField = textElements[0];
  let lastNameField = textElements[1];
  let emailField = textElements[2];
  let passwordField = textElements[3];

  let tcCheckbox = document.getElementsByClassName("checkbox")[0];

  // (3) Validate the data
  let errors = [];

  if (firstNameField.value.length === 0) {
    errors.push("Please enter first name!");
  }
  if (lastNameField.value.length === 0) {
    errors.push("Please enter last name!");
  }
  if (emailField.value.length === 0) {
    errors.push("Please enter valid email address!");
  }
  if (passwordField.value.length === 0) {
    errors.push("Please enter a password!");
  }
  if (tcCheckbox.checked === false) {
    errors.push("Please read and accept terms & conditions!");
  }

  // Reset both user-errors and user-success
  let errorsBox = document.getElementsByClassName("user-errors")[0];
  let successBox = document.getElementsByClassName("user-success")[0];

  errorsBox.style.display = "none";
  errorsBox.innerHTML = "";
  successBox.style.display = "none";

  if (errors.length > 0) {
    errorsBox.style.display = "block";
    errorsBox.innerHTML = errors.join("<br/>");
  } else {
    successBox.style.display = "block";
    successBox.innerHTML = "You have registered successfully!";
  }

  // Populate the registrationForm object (i.e, the FormData)
  registrationForm.append("firstName", firstNameField.value);
  registrationForm.append("lastName", lastNameField.value);
  registrationForm.append("email", emailField.value);
  registrationForm.append("password", passwordField.value);

  // (4) Save the data into FormData
  fetch("http://localhost:3001/user/signup", {
    /// signup insted of register
    method: "POST",
    // "headers": {
    //     'Content-Type': 'application/json'
    // },
    body: registrationForm,
  })
    .then(function (backendResponse) {
      return backendResponse.json();
    })
    .then(function (json) {
      console.log(json);
    })
    .catch(function (backendError) {
      console.log(backendError);
    });
}

document
  .getElementsByClassName("avatar")[0]
  .addEventListener("change", attachFile); /// change referse to the state of the upload file input... whene it changes then call attachFile function
