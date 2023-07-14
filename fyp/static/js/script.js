const body = document.querySelector("body"),
      modeToggle = body.querySelector(".mode-toggle");
      sidebar = body.querySelector("nav");
      sidebarToggle = body.querySelector(".sidebar-toggle");

let getMode = localStorage.getItem("mode");
if(getMode && getMode ==="dark"){
    body.classList.toggle("dark");
}

let getStatus = localStorage.getItem("status");
if(getStatus && getStatus ==="close"){
    sidebar.classList.toggle("close");
}

modeToggle.addEventListener("click", () =>{
    body.classList.toggle("dark");
    if(body.classList.contains("dark")){
        localStorage.setItem("mode", "dark");
    }else{
        localStorage.setItem("mode", "light");
    }
});

sidebarToggle.addEventListener("click", () => {
    sidebar.classList.toggle("close");
    if(sidebar.classList.contains("close")){
        localStorage.setItem("status", "close");
    }else{
        localStorage.setItem("status", "open");
    }
})


//For basic scan

window.onload = function(){
    slideOne();
    slideTwo();
}

let sliderOne = document.getElementById("slider-1");
let sliderTwo = document.getElementById("slider-2");
let displayValOne = document.getElementById("range1");
let displayValTwo = document.getElementById("range2");
let minGap = 0;
let sliderTrack = document.querySelector(".slider-track");
let sliderMaxValue = document.getElementById("slider-1").max;

function slideOne(){
    if(parseInt(sliderTwo.value) - parseInt(sliderOne.value) <= minGap){
        sliderOne.value = parseInt(sliderTwo.value) - minGap;
    }
    displayValOne.textContent = sliderOne.value;
    fillColor();
}
function slideTwo(){
    if(parseInt(sliderTwo.value) - parseInt(sliderOne.value) <= minGap){
        sliderTwo.value = parseInt(sliderOne.value) + minGap;
    }
    displayValTwo.textContent = sliderTwo.value;
    fillColor();
}
function fillColor(){
    percent1 = (sliderOne.value / sliderMaxValue) * 100;
    percent2 = (sliderTwo.value / sliderMaxValue) * 100;
    sliderTrack.style.background = `linear-gradient(to right, #dadae5 ${percent1}% , #3264fe ${percent1}% , #3264fe ${percent2}%, #dadae5 ${percent2}%)`;
}


//For basic scan

window.onload = function(){
    AslideOne();
    AslideTwo();
}

let AsliderOne = document.getElementById("Aslider-1");
let AsliderTwo = document.getElementById("Aslider-2");
let AdisplayValOne = document.getElementById("Arange1");
let AdisplayValTwo = document.getElementById("Arange2");
let AminGap = 0;
let AsliderTrack = document.querySelector(".Aslider-track");
let AsliderMaxValue = document.getElementById("Aslider-1").max;

function AslideOne(){
    if(parseInt(AsliderTwo.value) - parseInt(AsliderOne.value) <= AminGap){
        AsliderOne.value = parseInt(AsliderTwo.value) - AminGap;
    }
    AdisplayValOne.textContent = AsliderOne.value;
    AfillColor();
}
function AslideTwo(){
    if(parseInt(AsliderTwo.value) - parseInt(AsliderOne.value) <= AminGap){
        AsliderTwo.value = parseInt(AsliderOne.value) + AminGap;
    }
    AdisplayValTwo.textContent = AsliderTwo.value;
    AfillColor();
}
function AfillColor(){
    Apercent1 = (AsliderOne.value / AsliderMaxValue) * 100;
    Apercent2 = (AsliderTwo.value / AsliderMaxValue) * 100;
    AsliderTrack.style.background = `linear-gradient(to right, #dadae5 ${Apercent1}% , #3264fe ${Apercent1}% , #3264fe ${Apercent2}%, #dadae5 ${Apercent2}%)`;
}

//For Edit scan

window.onload = function(){
    EslideOne();
    EslideTwo();
}

let EsliderOne = document.getElementById("Eslider-1");
let EsliderTwo = document.getElementById("Eslider-2");
let EdisplayValOne = document.getElementById("Erange1");
let EdisplayValTwo = document.getElementById("Erange2");
let EminGap = 0;
let EsliderTrack = document.querySelector(".Eslider-track");
let EsliderMaxValue = document.getElementById("Eslider-1").max;

function EslideOne(){
    if(parseInt(EsliderTwo.value) - parseInt(EsliderOne.value) <= EminGap){
        EsliderOne.value = parseIntE(EsliderTwo.value) - EminGap;
    }
    EdisplayValOne.textContent = EsliderOne.value;
    EfillColor();
}
function EslideTwo(){
    if(parseInt(EsliderTwo.value) - parseInt(EsliderOne.value) <= EminGap){
        EsliderTwo.value = parseInt(EsliderOne.value) + EminGap;
    }
    EdisplayValTwo.textContent = EsliderTwo.value;
    EfillColor();
}
function EfillColor(){
    Epercent1 = (EsliderOne.value / EsliderMaxValue) * 100;
    Epercent2 = (EsliderTwo.value / EsliderMaxValue) * 100;
    EsliderTrack.style.background = `linear-gradient(to right, #dadae5 ${Epercent1}% , #3264fe ${Epercent1}% , #3264fe ${Epercent2}%, #dadae5 ${Epercent2}%)`;
}





// ssssssssss

