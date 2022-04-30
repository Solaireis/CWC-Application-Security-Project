function toggle(id) {
    var filters = JSON.parse(document.getElementById("checkedFilters").value);
    var checkbox = document.getElementById(id);

    if (checkbox.checked) {
        console.log("Is checked now");
        if (filters.indexOf(id) == -1) {
            filters.push(id)
        }
        console.log(id);
        console.log(filters);
    }
    else {
        console.log("Is not checked now")
        if (filters.indexOf(id) != -1) {
            console.log(filters.indexOf(id));
            filters.splice(filters.indexOf(id), 1);
        }
        console.log(id);
        console.log(filters);
    }
    document.getElementById('checkedFilters').value = JSON.stringify(filters);
}

function ticketToggle(ticketID) {
    document.getElementById("ticketID").value = ticketID;
    document.getElementById("ticketAction").value = "Toggle";
    document.getElementById("action-form").submit();
}

function ticketDelete(ticketID) {
    document.getElementById("ticketID").value = ticketID;
    document.getElementById("ticketAction").value = "Delete";
    document.getElementById("action-form").submit();
}

function allChoices() {
    document.getElementById('checkedFilters').value = JSON.stringify(['Open', 'Closed', 'Guest', 'Student', 'Teacher', 'General', 'Account', 'Business', 'Bugs', 'Jobs', 'News', 'Others']);
    var filters = document.getElementsByClassName("filter");
    for (var count = 0; count < filters.length; count++) {
        var filter = filters[count];
        filter.checked = true;
    }
}

function noChoices() {
    document.getElementById('checkedFilters').value = JSON.stringify([]);
    var filters = document.getElementsByClassName("filter");
    for (var count = 0; count < filters.length; count++) {
        var filter = filters[count];
        filter.checked = false;
    }
}
