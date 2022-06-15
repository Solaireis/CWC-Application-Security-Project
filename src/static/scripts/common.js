//////////////////START OF HAMBURGER MENU JAVASCRIPT //////////////////

let navbtn = document.getElementById("nav-icon");

function btnclick(){
    navbtn.classList.toggle("openTrue");
}

navbtn.addEventListener("click", btnclick);

////////////////// END OF HAMBURGER MENU JAVASCRIPT //////////////////

////////////////// Start of footer copyright year Javascript //////////////////

let footerCopright = document.getElementById("copyright_year").appendChild(document.createTextNode(new Date().getFullYear()));

////////////////// End of footer copyright year Javascript //////////////////

////////////////// Start of Go to top button Javascript //////////////////

var scrollToTopBtn = document.getElementById("topbutton");

window.onscroll = function(){
  scrollFunction();
};

function scrollFunction(){
  if(document.body.scrollTop > 20 || document.documentElement.scrollTop > 20) {
    scrollToTopBtn.classList.add("show");
  }
  else{
    scrollToTopBtn.classList.remove("show");
  }
}

scrollToTopBtn.addEventListener("click", scrollToTop);

var rootElement = document.documentElement;

function scrollToTop() {
  rootElement.scrollTo({
    top: 0, 
    behavior: "smooth" 
  });
}

////////////////// End of Go to top button Javascript //////////////////