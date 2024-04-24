function addListFields(
    daneZBazyDanych,
    id,
    sep,
    elementName = "dynamicField",
    spec = "textarea",
    classes = "form-control bg-dark formatuj-maly-font",
    idName = "additionalList",
    rowsAmount = "4",
    styleColor = "#c2c2c2",
    styleBorders = "#6a6a6a solid 1px",
    req = true,
    itemStyles = "no-border formatuj-margin form-control bg-dark formatuj-right",
    extraID = "list-container",
    removeButtonClass = "btn btn-outline-danger formatuj-maly-font formatuj-margin",
    removeButtonTextContent = "Usuń pole"
) {
    var pola_listy = daneZBazyDanych.split(sep);
    // Iteruj przez pola_listy
    pola_listy.forEach(function (value) {
        // Tworzymy nowy element input lub textarea, zależnie od wartości spec
        var inputElement;
        if (spec === 'textarea') {
            inputElement = document.createElement('textarea');
            inputElement.rows = rowsAmount;
        } else {
            inputElement = document.createElement('input');
            inputElement.type = 'text';
        }

        inputElement.name = elementName + id;
        inputElement.value = value;
        inputElement.className = classes;
        inputElement.style.color = styleColor;
        inputElement.style.border = styleBorders;
        inputElement.id = idName + id;
        inputElement.required = req;

        // Tworzymy nowy element div, który zawiera input/textarea i przycisk usuwania
        var listItem = document.createElement("div");
        listItem.className = itemStyles;
        listItem.appendChild(inputElement);

        // Przycisk usuwania
        var removeButton = document.createElement("button");
        removeButton.textContent = removeButtonTextContent;
        removeButton.type = "button";
        removeButton.className = removeButtonClass;
        removeButton.onclick = function () {
            listItem.remove();
        };

        listItem.appendChild(removeButton);

        // Dodajemy nowy element listy do kontenera
        var listContainer = document.getElementById(extraID + id);
        if (listContainer) {
            listContainer.appendChild(listItem);
        } else {
            console.error(`Element o identyfikatorze ${extraID + id} nie istnieje.`);
        }
    });
}



function addListItem(
    id, 
    elementName="dynamicField",
    spec="textarea", 
    classes="form-control bg-dark formatuj-maly-font",
    idName="additionalList",
    rowsAmount="4",
    styleColor="#c2c2c2",
    styleBorders="#6a6a6a solid 1px",
    req=true,
    itemStyles="no-border formatuj-margin form-control bg-dark formatuj-right",
    extraID="list-container",
    removeButtonClass="btn btn-outline-danger formatuj-maly-font formatuj-margin",
    removeButtonTextContent="Usuń pole"
) {
    var inputElement;

    if (spec === 'textarea') {
        // Tworzymy nowy element textarea
        inputElement = document.createElement('textarea');
        inputElement.rows = rowsAmount;
    } else {
        // Tworzymy nowy element input
        inputElement = document.createElement('input');
        inputElement.type = 'text';
    }

    inputElement.name = elementName + id; // Nazwa pola, którą możesz obsłużyć po stronie serwera
    inputElement.className = classes;
    inputElement.style.color = styleColor;
    inputElement.style.border = styleBorders;
    inputElement.id = idName;
    inputElement.required = req;

    var listItem = document.createElement("div");
    listItem.className = itemStyles;
    listItem.appendChild(inputElement);

    var removeButton = document.createElement("button");
    removeButton.textContent = removeButtonTextContent;
    removeButton.type = "button";
    removeButton.className = removeButtonClass;

    removeButton.onclick = function() {
        listItem.remove();
    };

    listItem.appendChild(removeButton);

    document.getElementById(extraID + id).appendChild(listItem);
}



// Funkcja do złączania zawartości pól listy w jeden string
function joinListFields(id, sep, elementName="dynamicField",) {
    var inputElements = document.getElementsByName(elementName+id);
    var values = [];

    // Iteruj przez wszystkie elementy input i dodaj ich wartości do tablicy
    for (var i = 0; i < inputElements.length; i++) {
        values.push(inputElements[i].value);
    }

    // Złącz tablicę w jeden string używając separatora #splx#
    var resultString = values.join(sep);

    // Wyświetl wynik w konsoli (możesz zmienić to na zapis do bazy danych)
    console.log(resultString);
    return resultString;
}


function prepareAndSubmitForm(postId, oldFotos=true) {
    // Sprawdź, czy wymagane pola są wypełnione
    var title = document.getElementById('title_' + postId).value;
    var introduction = document.getElementById('introduction_' + postId).value;
    var highlight = document.getElementById('Highlight_' + postId).value;

    var mainFoto = document.getElementById('mainFoto_' + postId).value;
    var contentFoto = document.getElementById('contentFoto_' + postId).value;

    var category = document.getElementById('category_' + postId).value;

    var dynamicFieldData = joinListFields(postId, '#splx#', 'dynamicField');
    var tagsFieldData = joinListFields(postId, ', ', 'dynamicTagsField');
    

    console.log("tags Field Data: " + tagsFieldData, "Dynamic field data: " + dynamicFieldData);

    if (!oldFotos) {
        if (!title || !introduction || !highlight || !mainFoto || !contentFoto || !tagsFieldData || !dynamicFieldData || !category ) {
            alert('Wypełnij wszystkie wymagane pola przed zapisaniem artykułu.');
            return;  // Zatrzymaj przesyłanie formularza
        };
    } else {
        if (!title || !introduction || !highlight || !tagsFieldData || !dynamicFieldData || !category) {
            alert('Wypełnij wszystkie wymagane pola przed zapisaniem artykułu.');
            return;  // Zatrzymaj przesyłanie formularza
        };
    }

    // Pobierz dane za pomocą funkcji joinListFields i ustaw wartości ukrytych pól formularza
    

    document.getElementById('tagsFieldData_'+postId).value = tagsFieldData;
    document.getElementById('dynamicFieldData_'+postId).value = dynamicFieldData;

    // Znajdź formularz i wyślij go
    var form = document.getElementById('editPost_'+postId);
    form.submit();
}

// Funkcja do złączania zawartości pól dynamicznego opisu oferty do json na podstawie atrybutu data-type
// wszystkie elementy wygenerowane za pomocą funkcji addCustomElement mają atrybut data-type w którym jest zawarty rodzaj pola
// funkcja rozrónia pola pomiedzy li i inne. pola li mają strukturę listy json gdzie kluczem jest "li" a wartością lista. 
// inne pola ("p", "strong", "h1", "h2", "h3", "h1-strong", "h2-strong", "h3-strong") mają zawsze warotść string
// [{"li": ["wartość1", "wartość2", "wartość3"]}, {"p": "wartość"}, itd...]
// funkcja znajduje kontener wygenerowanych pół na podstawie nazwy i id a nastepnie iteruje przez niego i tworzy listę json
// które zawierają obiekty gdzie klucze to data-type a wartości to: dla li - lista  wartości, dla innych - pojedyncze stringi.

function joinToDynamicDescription(id, elementName="list-container") {
    // Używamy querySelectorAll zamiast getElementsByName, dodajemy selektor 'input' i 'textarea'
    // oraz inne elementy, które mogą zawierać dane
    var container = document.getElementById(`${elementName}${id}`);
    var inputElements = container.querySelectorAll('input, textarea');

    var resultJsonList = [];

    // Iteruj przez wszystkie elementy input i textarea
    inputElements.forEach(element => {
        const dataType = element.getAttribute('data-type');
        
        // Sprawdź czy pole to 'li' i odpowiednio przetwarzaj
        if (dataType === 'li') {
            // Jeśli już istnieje obiekt z kluczem 'li', dodaj do niego nową wartość
            let liObject = resultJsonList.find(item => item.hasOwnProperty('li'));
            if (liObject) {
                liObject.li.push(element.value);
            } else {
                // Jeśli nie ma jeszcze obiektu 'li', stwórz nowy
                resultJsonList.push({li: [element.value]});
            }
        } else {
            // Dla pozostałych typów danych, twórz pojedyncze obiekty z kluczem i wartością
            let object = {};
            object[dataType] = element.value;
            resultJsonList.push(object);
        }
    });

    // Wyświetl wynik w konsoli
    console.log(resultJsonList);

    return resultJsonList;
}

// function blobUrlToFile(blobUrl, fileName) {
//     return fetch(blobUrl)
//         .then(response => response.blob())
//         .then(blob => new File([blob], fileName, { type: blob.type }));
// }



function prepareAndSubmitRentOfferForm(offerId, oldFotos=true) {
    // Pobieranie wartości z formularza
    var title = document.getElementById('title_' + offerId).value;
    var rodzajNieruchomosci = document.getElementById('RodzajNieruchomosci_' + offerId).value;
    var lokalizacja = document.getElementById('Lokalizacja_' + offerId).value;
    var cena = document.getElementById('Cena_' + offerId).value;
    var opis = joinToDynamicDescription(offerId, "list-container");
    var opisJsonString = JSON.stringify(opis);

    // Pobieranie zdjęć z listy
    var fotoList = document.getElementById(offerId + '-fileList');
    var zdjecia = [];

    fotoList.childNodes.forEach(child => {
        console.log(child.file);
        if (child.file) {  // Sprawdź, czy element li ma przypisany plik
            console.log('child.file', child.file);
            zdjecia.push(child.file);
        }
    });
    // if (fotoList && fotoList.childNodes.length > 0) {
    //     fotoList.childNodes.forEach(child => {
    //         console.log(child.tagName); // Sprawdź, czy rzeczywiście dostajesz tagi LI
    //         console.log(child.file);
    //         if (child.tagName === 'LI' && child.file) {
    //             console.log('Dodaję plik:', child.file.name); // Sprawdź, czy pliki są dodawane
    //             zdjecia.push(child.file);
    //         }
    //     });
    // }

    // Sprawdzanie, czy wszystkie wymagane pola są wypełnione
    if (!oldFotos) {
        if (!title || !rodzajNieruchomosci || !lokalizacja || !cena || zdjecia.length === 0 || !opis) {
            alert('Wypełnij wszystkie wymagane pola przed zapisaniem oferty.');
            return;  // Zatrzymaj przesyłanie formularza
        }
    } else {
        if (!title || !rodzajNieruchomosci || !lokalizacja || !cena || !opis) {
            alert('Wypełnij wszystkie wymagane pola przed zapisaniem oferty.');
            return;  // Zatrzymaj przesyłanie formularza
        }
    }

    // Dodawanie zdjęć jako FormData
    var formData = new FormData();
    zdjecia.forEach(file => {
        formData.append('photos[]', file);
        console.log('Dodaję plik:', file.name);
    });

    // Wyświetl zawartość FormData przed wysłaniem
    for (var pair of formData.entries()) {
        console.log(pair[0]+ ', ' + pair[1]);
    }


    // Dodanie pozostałych danych do FormData
    formData.append('title', title);
    formData.append('rodzajNieruchomosci', rodzajNieruchomosci);
    formData.append('lokalizacja', lokalizacja);
    formData.append('cena', cena);
    formData.append('opis', opisJsonString);

    // Wysyłanie formularza za pomocą AJAX (fetch API)
    fetch('/save-rent-offer', {
        method: 'POST',
        body: formData
    }).then(response => {
        if (response.ok) {
            alert('Oferta została pomyślnie zapisana.');
            return response.json();
        } else {
            throw new Error('Problem z serwerem');
        }
    }).then(data => {
        console.log(data);
    }).catch(error => {
        alert('Wystąpił błąd: ' + error.message);
    });
}



function newUserSubmitForm(logins_allowed, email_allowed, name_allowed) {
    // Zmienna do śledzenia, czy formularz jest wypełniony poprawnie
    let formIsValid = true;

    // Funkcja pomocnicza do dodawania/usuwania klasy ostrzeżenia
    function toggleWarning(elementId, condition) {
        const element = document.getElementById(elementId);
        if (condition) {
            element.classList.add('input-warning');
            formIsValid = false; // Ustawiamy, że formularz jest niepoprawny
        } else {
            element.classList.remove('input-warning');
        }
    }

    // Sprawdzenie loginu
    var login = document.getElementById('Login_new_user').value;
    toggleWarning('Login_new_user', logins_allowed.includes(login) || login === '');

    // Sprawdzenie emaila
    var email = document.getElementById('Email_new_user').value;
    toggleWarning('Email_new_user', email_allowed.includes(email) || email === '');

    // Sprawdzenie Nazwiska
    var name = document.getElementById('Name_new_user').value;
    toggleWarning('Name_new_user', name_allowed.includes(name) || name === '');

    // Sprawdzenie innych pól

    // var avatar = document.getElementById('Avatar_new_user').value;
    var role = document.getElementById('Stanowsko_new_user').value;
    var opis = document.getElementById('Description_new_user').value;


    // toggleWarning('Avatar_new_user', !avatar);
    toggleWarning('Stanowsko_new_user', !role);
    toggleWarning('Description_new_user', !opis);

    // Jeżeli którykolwiek z testów nie przeszedł, nie wysyłaj formularza
    if (!formIsValid) {
        return;
    }

    // Znajdź formularz i wyślij go
    var form = document.getElementById('new_user');
    form.submit();
}


function justSubmitOneElementForm(elementName, elementId, formName) {
    // Sprawdź, czy wymagane pola są wypełnione
    var oneElement = document.getElementById(elementName + elementId).value;
    // console.log('oneElement', oneElement);
    if (!oneElement) {
        alert('Wypełnij wszystkie wymagane pola przed zapisaniem artykułu.');
        return;  // Zatrzymaj przesyłanie formularza
    };
  
    var form = document.getElementById(formName+elementId);
    form.submit();
}

function previewImage(input, previewId, targetWidth, targetHeight, errorMargin) {
    var preview = document.getElementById(previewId);
    var file = input.files[0];
    var reader = new FileReader();

    reader.onloadend = function () {
        var img = new Image();
        img.src = reader.result;

        img.onload = function () {
            if (
                img.width >= targetWidth - errorMargin && img.width <= targetWidth + errorMargin &&
                img.height >= targetHeight - errorMargin && img.height <= targetHeight + errorMargin
            ) {
                preview.src = reader.result;
            } else {
                alert('Nieprawidłowy rozmiar obrazu. Wymagane wymiary to ' + targetWidth + 'x' + targetHeight + ' z marginesem błędu ' + errorMargin + ' pikseli. Twój obrazek ma ' + img.width + 'x' + img.height);
                input.value = '';  // Wyczyszczenie inputa
                preview.src = '';  // Wyczyszczenie podglądu
            }
        };
    }

    if (file) {
        reader.readAsDataURL(file);
    } else {
        preview.src = "";
    }
}



function przeciagnij(event) {
    event.dataTransfer.setData("text/plain", event.target.textContent);
    event.dataTransfer.setData("shape", event.target.getAttribute("data-shape"));
    event.dataTransfer.setData("image-url", event.target.getAttribute("data-image-url"));
    event.target.classList.add("clone"); // Oznacz element jako klon
}

function dopuszczalnePrzesuniecie(event) {
    event.preventDefault();
}

function upusc(area, event) {
    event.preventDefault();
    const pracownikImie = event.dataTransfer.getData("text/plain");
    const pracownikShape = event.dataTransfer.getData("shape");
    const pracownikImageUrl = event.dataTransfer.getData("image-url");

    const pracownikDiv = document.createElement("div");
    pracownikDiv.textContent = pracownikImie;
    pracownikDiv.draggable = true;
    pracownikDiv.className = "dostepnyPracownik";
    pracownikDiv.setAttribute("data-shape", pracownikShape);
        
    if (pracownikImageUrl) {
        pracownikDiv.setAttribute("data-image-url", pracownikImageUrl);
        pracownikDiv.style.backgroundImage = `url('${pracownikImageUrl}')`; 
    }

    pracownikDiv.addEventListener("dragstart", przeciagnij);

    if (area === 'home') {
        if (home.childElementCount < 4 && !czyPracownikIstnieje(home, pracownikImie) && !czyPracownikIstnieje(team, pracownikImie)) {
            home.appendChild(pracownikDiv);
            usunPracownikaZListy('dostepniPracownicy', pracownikImie);
            usunPracownikaZListy('team', pracownikImie);
        } else {
            alert("Można publikować maksymalnie 4 pracowników na stronie głównej. Pracownik przeniesiony do Team.");
        }
    } else if (area === 'team' && !czyPracownikIstnieje(home, pracownikImie) && !czyPracownikIstnieje(team, pracownikImie)) {
        team.appendChild(pracownikDiv);
        usunPracownikaZListy('dostepniPracownicy', pracownikImie);
        usunPracownikaZListy('home', pracownikImie);
    } else if (area === 'dostepniPracownicy' && !czyPracownikIstnieje(dostepniPracownicy, pracownikImie)) {
        document.getElementById('dostepniPracownicy').appendChild(pracownikDiv);
        usunPracownikaZListy('home', pracownikImie);
        usunPracownikaZListy('team', pracownikImie);
    } 
    else {
        // Jeśli próbujesz przeciągnąć z "home" do "team" lub odwrotnie, zablokuj operację
        alert("Nie można przeciągać między 'home' a 'team'.");
    }
}

function czyPracownikIstnieje(sekcja, pracownikImie) {
    const pracownicy = sekcja.querySelectorAll('div');
    let istnieje = false;
    pracownicy.forEach(pracownik => {
        if (pracownik.textContent === pracownikImie) {
            istnieje = true;
        }
    });

    return istnieje;
}

function usunPracownikaZListy(sekcja, pracownikImie) {
    const pracownicy = document.getElementById(sekcja).querySelectorAll('div');
    pracownicy.forEach(pracownik => {
        if (pracownik.textContent === pracownikImie) {
            pracownik.remove();
        }
    });
}

function pobierzKolejnosc(sekcja) {
    const elementy = sekcja.querySelectorAll('div');
    const kolejnosc = Array.from(elementy).map(element => element.textContent);
    console.log(`Kolejność w sekcji ${sekcja}:`, kolejnosc);
    return kolejnosc;
}

function pobierzIKonsolujKolejnosc(sekcjaId) {
    const sekcja = document.getElementById(sekcjaId);
    const elementy = sekcja.querySelectorAll('div');
    const kolejnosc = Array.from(elementy).map(element => element.textContent);
    
    console.log(`Kolejność w sekcji ${sekcjaId}:`, kolejnosc);
}

function addCustomElement(id, elementType, elementContent) {
    var container = document.getElementById('list-container' + id);
    var buttonContainer = document.getElementById('button-container' + id) || createButtonContainer(id, container);
    var newElement;
    
    if (elementType.includes('li')) {
        newElement = document.createElement('input');
        newElement.type = 'text';
        newElement.className = 'form-control bg-dark custom-element mb-1';
        newElement.style.color = '#c2c2c2';
        newElement.style.border = '#6a6a6a solid 1px';
        newElement.setAttribute('data-type', elementType);
        newElement.setAttribute('placeholder', `Dodaj treść dla atrybutu <${elementType}>`);
        toggleButtons(false);
    } else {
        newElement = document.createElement('textarea');
        newElement.rows = 4;
        newElement.className = 'form-control bg-dark custom-element mb-1';
        newElement.style.color = '#c2c2c2';
        newElement.style.border = '#6a6a6a solid 1px';
        newElement.setAttribute('data-type', elementType);
        newElement.setAttribute('placeholder', `Dodaj treść dla atrybutu <${elementType}>`);
    }

    newElement.value = elementContent || '';
    var elementWrapper = document.createElement('div');
    elementWrapper.className = "element-wrapper mb-1";
    elementWrapper.appendChild(newElement);

    var removeButton = document.createElement('button');
    removeButton.textContent = 'Usuń pozycję';
    removeButton.className = 'btn btn-outline-danger btn-sm mb-1';
    removeButton.onclick = function() {
        elementWrapper.remove();
        if (!container.querySelector('[data-type^="li"]')) {
            toggleButtons(true);
            buttonContainer.remove();
        }
    };
    elementWrapper.appendChild(removeButton);
    container.insertBefore(elementWrapper, buttonContainer);

    if (elementType.includes('li') && !document.querySelector('.end-list-button')) {
        createListManagementButtons(buttonContainer);
    }
}

function createButtonContainer(id, container) {
    var buttonContainer = document.createElement('div');
    buttonContainer.id = 'button-container' + id;
    buttonContainer.className = 'button-container mb-1';
    container.appendChild(buttonContainer);
    return buttonContainer;
}

function createListManagementButtons(buttonContainer) {
    var endListButton = document.createElement('button');
    endListButton.textContent = 'Zakończ listę';
    endListButton.className = 'btn btn-outline-secondary btn-sm end-list-button mb-1';
    endListButton.onclick = function() {
        buttonContainer.remove();
        toggleButtons(true);
    };
    buttonContainer.appendChild(endListButton);
}

function toggleButtons(show) {
    var allButtons = document.querySelectorAll('.add-button');
    var listButtons = document.querySelectorAll('.add-list-item-button'); // Wybiera przyciski dodające elementy listy

    allButtons.forEach(button => {
        if (button.classList.contains('add-list-item-button')) {
            // Przyciski list są pokazywane tylko gdy lista jest aktywna (show === false)
            button.style.display = show ? 'none' : 'inline-block';
        } else {
            // Wszystkie inne przyciski są ukrywane, gdy lista jest aktywna (show === false)
            button.style.display = show ? 'inline-block' : 'none';
        }
    });
}

