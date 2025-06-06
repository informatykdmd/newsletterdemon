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
        if (removeButtonTextContent === '') {
            removeButton.textContent = removeButtonTextContent;
        } else {
            removeButton.innerHTML = '<i class="bi bi-trash3-fill" style="font-size: 15px !important;"></i>';
        }

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
    itemStyles="no-border formatuj-margin form-control bg-dark formatuj-right tylko-klej",
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
    if (removeButtonTextContent === '') {
        removeButton.textContent = removeButtonTextContent;
    } else {
        removeButton.innerHTML = '<i class="bi bi-trash3-fill" style="font-size: 15px !important;"></i>';
    }
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

    // Złącz tablicę w jeden string używając separatora np. #splx#
    var resultString = values.join(sep);

    // Wyświetl wynik w konsoli (możesz zmienić to na zapis do bazy danych)
    // console.log(resultString);
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
    

    // console.log("tags Field Data: " + tagsFieldData, "Dynamic field data: " + dynamicFieldData);

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

function prepareAndSubmitCareerForm(careerId) {
    let formIsValid = true;

    function toggleWarning(elementId, condition) {
        const element = document.getElementById(elementId);
        if (condition) {
            element.classList.add('input-warning');
            formIsValid = false;
        } else {
            element.classList.remove('input-warning');
        }
    }

    // Pobieranie wartości z formularza
    var title = document.getElementById('title_' + careerId).value;
    var startDate = document.getElementById('start_' + careerId).value;
    var salary = document.getElementById('salary_' + careerId).value;
    var employmentType = document.getElementById('employmenttype_' + careerId).value;
    var location = document.getElementById('lokalizacja_' + careerId).value;
    var brand = document.getElementById('brand_' + careerId).value;
    var email = document.getElementById('email_' + careerId).value;
    var offerID = document.getElementById('OfferID_' + careerId).value;

    // Pobranie surowego tekstu z contenteditable (usuwanie znaczników HTML)
    var jobDescription = document.getElementById('description_' + careerId).innerText;
    var requirementsDescription = document.getElementById('requirementsDescription_' + careerId).innerText;

    // Łączenie dynamicznych list
    var dynamicRequirementsList = joinListFields(careerId, '#splx#', 'dynamicRequirementsList_');
    var dynamicBenefitsList = joinListFields(careerId, '#splx#', 'dynamicBenefitsList_');

    // Sprawdzanie, czy wszystkie wymagane pola są wypełnione
    toggleWarning('title_' + careerId, !title);
    toggleWarning('salary_' + careerId, !salary);
    toggleWarning('start_' + careerId, !startDate);
    toggleWarning('employmenttype_' + careerId, !employmentType);
    toggleWarning('lokalizacja_' + careerId, !location);
    toggleWarning('brand_' + careerId, !brand);
    toggleWarning('email_' + careerId, !email);
    toggleWarning('description_' + careerId, !jobDescription);
    toggleWarning('requirementsDescription_' + careerId, !requirementsDescription);

    // Jeżeli którykolwiek z testów nie przeszedł, nie wysyłaj formularza
    if (!formIsValid) {
        return;
    }

    // Tworzenie FormData i dodanie wartości
    let formData = new FormData();
    formData.append('title', title);
    formData.append('startdate', startDate);
    formData.append('salary', salary);
    formData.append('employmenttype', employmentType);
    formData.append('location', location);
    formData.append('brand', brand);
    formData.append('email', email);
    formData.append('jobDescription', jobDescription);
    formData.append('requirementsDescription', requirementsDescription);
    formData.append('dynamicRequirementsList', dynamicRequirementsList);
    formData.append('dynamicBenefitsList', dynamicBenefitsList);
    formData.append('OfferID', offerID);


    // Wysyłanie formularza za pomocą AJAX (fetch API)
    fetch('/save-career-offer', {
        method: 'POST',
        body: formData
    }).then(response => {
        if (response.ok) {
            return response.json();
        } else {
            throw new Error('Problem z serwerem');
        }
    }).then(data => {
        if (data.success == true) {
            var form = document.getElementById('jobOffer_' + careerId);
            form.reset();
            window.location.href = '/career';
        } else if (data.error) {
            alert('Wystąpił błąd: ' + data.error);
        }
    }).catch(error => {
        alert('Wystąpił błąd: ' + error.message);
    });
}

// Funkcja do złączania zawartości pól dynamicznego opisu oferty do json na podstawie atrybutu data-type
// wszystkie elementy wygenerowane za pomocą funkcji addCustomElement mają atrybut data-type w którym jest zawarty rodzaj pola
// funkcja rozrónia pola pomiedzy li i inne. pola li mają strukturę listy json gdzie kluczem jest "li" a wartością lista. 
// inne pola ("p", "strong", "h1", "h2", "h3", "h1-strong", "h2-strong", "h3-strong") mają zawsze warotść string
// [{"li": ["wartość1", "wartość2", "wartość3"]}, {"p": "wartość"}, itd...]
// funkcja znajduje kontener wygenerowanych pół na podstawie nazwy i id a nastepnie iteruje przez niego i tworzy listę json
// które zawierają obiekty gdzie klucze to data-type a wartości to: dla li - lista  wartości, dla innych - pojedyncze stringi.
function encodeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function joinToDynamicDescription(id, elementName="list-container") {
    // Używamy querySelectorAll zamiast getElementsByName, dodajemy selektor 'input' i 'textarea'
    // oraz inne elementy, które mogą zawierać dane
    var container = document.getElementById(`${elementName}${id}`);
    var inputElements = container.querySelectorAll('input, textarea');

    var resultJsonList = [];

    // Iteruj przez wszystkie elementy input i textarea
    inputElements.forEach(element => {
        const dataType = element.getAttribute('data-type');
        const encodedValue = encodeHtml(element.value); // Koduj każdą wartość przed użyciem
        // Sprawdź czy pole to 'li' i odpowiednio przetwarzaj
        if (dataType === 'li') {
            // Jeśli już istnieje obiekt z kluczem 'li', dodaj do niego nową wartość
            let liObject = resultJsonList.find(item => item.hasOwnProperty('li'));
            if (liObject) {
                liObject.li.push(encodedValue);
            } else {
                // Jeśli nie ma jeszcze obiektu 'li', stwórz nowy
                resultJsonList.push({li: [encodedValue]});
            }
        } else {
            // Dla pozostałych typów danych, twórz pojedyncze obiekty z kluczem i wartością
            let object = {};
            object[dataType] = encodedValue;
            resultJsonList.push(object);
        }
    });

    // Wyświetl wynik w konsoli
    // console.log(resultJsonList);

    return resultJsonList;
}

function prepareAndSubmitHiddenFBform(offerId, oldFotos=true) {
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

    // Pobieranie wartości z formularza
    var title = document.getElementById('title_' + offerId).value;
    var description = document.getElementById('description_' + offerId).innerText;
    
    // var category = document.getElementById('category_' + offerId).value;
    var offerIDbox = document.getElementById('OfferID_' + offerId).value;
    // var created_by = document.getElementById('setCreated_by_' + offerId).value;
    var author = document.getElementById('author_' + offerId).value;
    var target = document.getElementById('target_' + offerId).value;

    // Pobieramy wartości
    var category_value = document.getElementById('to_splitted_category_' + offerId).value;


    // Sprawdzamy, czy obie wartości zawierają znak '/', bo tylko wtedy możemy je podzielić
    if (!category_value.includes('/')) {
        console.error("Niepoprawny format wartości!");
        return; // Zatrzymujemy wysyłkę, jeśli któraś z wartości nie zawiera '/'
    }

    // Dzielimy wartości
    const category_splitted = category_value.split('/')[1];
    const created_by_splitted = category_value.split('/')[0];

    // Pobieranie zdjęć z listy
    var fotoList = document.getElementById(offerId + '-fileList');
    // console.log('fotoList: ', fotoList);
    var zdjecia = [];
    var oldFotos_list = [];

    fotoList.childNodes.forEach(child => {
        if (child.file) {  // Sprawdź, czy element li ma przypisany plik
            zdjecia.push(child.file);
        } else {
            oldFotos_list.push(child.textContent);
        }
    });

    // Sprawdzanie, czy wszystkie wymagane pola są wypełnione
    toggleWarning('title_' + offerId, !title);
    toggleWarning('description_' + offerId, !description);
    toggleWarning('to_splitted_category_' + offerId, !category_splitted);


    // Dodawanie zdjęć jako FormData
    var formData = new FormData();
    zdjecia.forEach(file => {
        formData.append('photos[]', file);
    });

    // Dodawanie istniejących nazw zdjęć jako FormData
    oldFotos_list.forEach(url => {
        formData.append('oldPhotos[]', url);
    });

    // Dodawanie istniejących nazw zdjęć
    fotoList.childNodes.forEach(child => {
        if (child.textContent.includes('(')) {
            formData.append('allPhotos[]', child.textContent.split(' (')[0]);
        } else {
            formData.append('allPhotos[]', child.textContent);
        }
    });


    // Dodanie pozostałych danych do FormData
    formData.append('title', title);
    formData.append('description', description);
    formData.append('category', category_splitted);
    formData.append('created_by', created_by_splitted);
    formData.append('author', author);
    formData.append('target', target);
 
    formData.append('offerID', offerIDbox);

    // console.log('formData', formData);

    // Jeżeli którykolwiek z testów nie przeszedł, nie wysyłaj formularza
    if (!formIsValid) {
        return;
    }

    // console.log('formData: ', formData);
    // Wysyłanie formularza za pomocą AJAX (fetch API)
    fetch('/save-hidden-campaigns', {
        method: 'POST',
        body: formData
    }).then(response => {
        // console.log('response: ', response);
        if (response.ok) {
            // alert('Oferta została pomyślnie zapisana.');
            // console.log('response: ', response);
            return response.json();
        } else {
            // console.log('xxx:', data);

            throw new Error('Problem z serwerem');
        }
    }).then(data => {
        // console.log('data:', data);
        // console.log('data.seccess:', data.success);
        if (data.success == true) {
            // console.log('xxx:', data);
            var form = document.getElementById('hiddencampaigns_' + offerId);
            form.reset();
            window.location.href = '/hidden-campaigns';
        } else if (data.error) {
            
        }
    }).catch(error => {
        alert('Wystąpił błąd: ' + error.message);
    });
}

function prepareAndSubmitRentOfferForm(offerId, oldFotos=true) {
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

    // Pobieranie wartości z formularza
    var title = document.getElementById('title_' + offerId).value;
    var rodzajNieruchomosci = document.getElementById('RodzajNieruchomosci_' + offerId).value;
    var lokalizacja = document.getElementById('Lokalizacja_' + offerId).value;
    var cena = document.getElementById('Cena_' + offerId).value;
    var opis = joinToDynamicDescription(offerId, "list-container");
    var opisJsonString = JSON.stringify(opis);

    try {
        var lat = document.getElementById('lat_' + offerId).value;
        var lon = document.getElementById('lon_' + offerId).value;
    } catch {
        var lat = '';
        var lon = '';
    }
    
    var rokBudowy = document.getElementById('RokBudowy_' + offerId).value;
    var stan = document.getElementById('StanWykonczenia_' + offerId).value;
    var nrKW = document.getElementById('NumerKW_' + offerId).value;
    var czynsz = document.getElementById('Czynsz_' + offerId).value;
    var kaucja = document.getElementById('Kaucja_' + offerId).value;
    var metraz = document.getElementById('Metraz_' + offerId).value;
    var powDzialki = document.getElementById('PowierzchniaDzialki_' + offerId).value;
    var liczbaPieter = document.getElementById('LiczbaPieter_' + offerId).value;
    var liczbaPokoi = document.getElementById('LiczbaPokoi_' + offerId).value;
    var techBudowy = document.getElementById('TechnologiaBudowy_' + offerId).value;
    var rodzajZabudowy = document.getElementById('RodzajZabudowy_' + offerId).value;
    var umeblowanie = document.getElementById('Umeblowanie_' + offerId).value;
    var kuchnia = document.getElementById('FormaKuchni_' + offerId).value;
    var dodatkoweInfo = document.getElementById('InformacjeDodatkowe_' + offerId).value;
    var offerIDbox = document.getElementById('OfferID_' + offerId).value;

    // Pobieranie zdjęć z listy
    var fotoList = document.getElementById(offerId + '-fileList');
    // console.log('fotoList: ', fotoList);
    var zdjecia = [];
    var oldFotos_list = [];

    fotoList.childNodes.forEach(child => {
        if (child.file) {  // Sprawdź, czy element li ma przypisany plik
            zdjecia.push(child.file);
        } else {
            oldFotos_list.push(child.textContent);
        }
    });
    // console.log('oldFotos_list', oldFotos_list);

    // Sprawdzanie, czy wszystkie wymagane pola są wypełnione
    toggleWarning('title_' + offerId, !title);
    toggleWarning('RodzajNieruchomosci_' + offerId, !rodzajNieruchomosci);
    toggleWarning('Lokalizacja_' + offerId, !lokalizacja);
    toggleWarning('Cena_' + offerId, !cena);
    toggleWarning('Metraz_' + offerId, !metraz);

    if (!oldFotos) {
        if (zdjecia.length === 0) {
            const elementzdjecia = document.getElementById(offerId+'-drop-area');
    
            elementzdjecia.classList.add('input-warning');
            formIsValid = false; // Ustawiamy, że formularz jest niepoprawny
    
            return;  // Zatrzymaj przesyłanie formularza
        }
    } else {
        if (zdjecia.length === 0 && oldFotos_list.length === 0) {
            const elementzdjecia = document.getElementById(offerId+'-drop-area');
    
            elementzdjecia.classList.add('input-warning');
            formIsValid = false; // Ustawiamy, że formularz jest niepoprawny
    
            return;  // Zatrzymaj przesyłanie formularza
        }
    }
    
    if (opis.length === 0 || opis[0].p === "") {
        const elementopisJsonString = document.getElementById('list-container'+offerId);

        elementopisJsonString.classList.add('input-warning');
        formIsValid = false; // Ustawiamy, że formularz jest niepoprawny
        return;  // Zatrzymaj przesyłanie formularza
    } 

    // Dodawanie zdjęć jako FormData
    var formData = new FormData();
    zdjecia.forEach(file => {
        formData.append('photos[]', file);
    });

    // Dodawanie istniejących nazw zdjęć jako FormData
    oldFotos_list.forEach(url => {
        formData.append('oldPhotos[]', url);
    });

    // Dodawanie istniejących nazw zdjęć
    fotoList.childNodes.forEach(child => {
        if (child.textContent.includes('(')) {
            formData.append('allPhotos[]', child.textContent.split(' (')[0]);
        } else {
            formData.append('allPhotos[]', child.textContent);
        }
    });

    // Dodanie pozostałych danych do FormData
    formData.append('title', title);
    formData.append('rodzajNieruchomosci', rodzajNieruchomosci);
    formData.append('lokalizacja', lokalizacja);
    formData.append('cena', cena);
    formData.append('opis', opisJsonString);

    formData.append('lat', lat);
    formData.append('lon', lon);
    formData.append('rokBudowy', rokBudowy);
    formData.append('stan', stan);
    formData.append('nrKW', nrKW);
    formData.append('czynsz', czynsz);
    formData.append('kaucja', kaucja);
    formData.append('metraz', metraz);
    formData.append('powDzialki', powDzialki);
    formData.append('liczbaPieter', liczbaPieter);
    formData.append('liczbaPokoi', liczbaPokoi);
    formData.append('techBudowy', techBudowy);
    formData.append('rodzajZabudowy', rodzajZabudowy);
    formData.append('umeblowanie', umeblowanie);
    formData.append('kuchnia', kuchnia);
    formData.append('dodatkoweInfo', dodatkoweInfo);
    formData.append('offerID', offerIDbox);

    // Jeżeli którykolwiek z testów nie przeszedł, nie wysyłaj formularza
    if (!formIsValid) {
        return;
    }

    // Wysyłanie formularza za pomocą AJAX (fetch API)
    fetch('/save-rent-offer', {
        method: 'POST',
        body: formData
    }).then(response => {
        // console.log('response: ', response);
        if (response.ok) {
            // alert('Oferta została pomyślnie zapisana.');
            // console.log('response: ', response);
            return response.json();
        } else {
            // console.log('xxx:', data);

            throw new Error('Problem z serwerem');
        }
    }).then(data => {
        // console.log('data:', data);
        // console.log('data.seccess:', data.success);
        if (data.success == true) {
            // console.log('xxx:', data);
            var form = document.getElementById('rentOffer_' + offerId);
            form.reset();
            window.location.href = '/estate-ads-rent';
        } else if (data.error) {
            
        }
    }).catch(error => {
        alert('Wystąpił błąd: ' + error.message);
    });
}

function prepareAndSubmitSellOfferForm(offerId, oldFotos=true) {
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

    // Pobieranie wartości z formularza
    var title = document.getElementById('title_' + offerId).value;
    var typNieruchomosci = document.getElementById('TypNieruchomosci_' + offerId).value;
    var rynek = document.getElementById('Rynek_' + offerId).value;
    var lokalizacja = document.getElementById('Lokalizacja_' + offerId).value;
    var cena = document.getElementById('Cena_' + offerId).value;
    var opis = joinToDynamicDescription(offerId, "list-container");
    var opisJsonString = JSON.stringify(opis);

    try {
        var lat = document.getElementById('lat_' + offerId).value;
        var lon = document.getElementById('lon_' + offerId).value;
    } catch {
        var lat = '';
        var lon = '';
    }
    
    var rokBudowy = document.getElementById('RokBudowy_' + offerId).value;
    var stan = document.getElementById('StanWykonczenia_' + offerId).value;
    var nrKW = document.getElementById('NumerKW_' + offerId).value;
    var typDomu = document.getElementById('TypDomu_' + offerId).value;
    var przeznaczenieLokalu = document.getElementById('PrzeznaczenieLokalu_' + offerId).value;
    var metraz = document.getElementById('Metraz_' + offerId).value;
    var poziom = document.getElementById('Poziom_' + offerId).value;
    var liczbaPieter = document.getElementById('LiczbaPieter_' + offerId).value;
    var liczbaPokoi = document.getElementById('LiczbaPokoi_' + offerId).value;
    var techBudowy = document.getElementById('TechnologiaBudowy_' + offerId).value;
    var rodzajZabudowy = document.getElementById('RodzajZabudowy_' + offerId).value;
    var rodzajNieruchomosci = document.getElementById('RodzajNieruchomosci_' + offerId).value;
    var kuchnia = document.getElementById('FormaKuchni_' + offerId).value;
    var dodatkoweInfo = document.getElementById('InformacjeDodatkowe_' + offerId).value;
    var offerIDbox = document.getElementById('OfferID_' + offerId).value;

    // Pobieranie zdjęć z listy
    var fotoList = document.getElementById(offerId + '-fileList');
    // console.log('fotoList: ', fotoList);
    var zdjecia = [];
    var oldFotos_list = [];

    fotoList.childNodes.forEach(child => {
        if (child.file) {  // Sprawdź, czy element li ma przypisany plik
            zdjecia.push(child.file);
        } else {
            oldFotos_list.push(child.textContent);
        }
    });
    // console.log('oldFotos_list', oldFotos_list);

    // Sprawdzanie, czy wszystkie wymagane pola są wypełnione
    toggleWarning('title_' + offerId, !title);
    toggleWarning('TypNieruchomosci_' + offerId, !typNieruchomosci);
    toggleWarning('Rynek_' + offerId, !rynek);
    toggleWarning('Lokalizacja_' + offerId, !lokalizacja);
    toggleWarning('Cena_' + offerId, !cena);
    toggleWarning('Metraz_' + offerId, !metraz);


    if (!oldFotos) {
        if (zdjecia.length === 0) {
            const elementzdjecia = document.getElementById(offerId+'-drop-area');
    
            elementzdjecia.classList.add('input-warning');
            formIsValid = false; // Ustawiamy, że formularz jest niepoprawny
    
            return;  // Zatrzymaj przesyłanie formularza
        }
    } else {
        if (zdjecia.length === 0 && oldFotos_list.length === 0) {
            const elementzdjecia = document.getElementById(offerId+'-drop-area');
    
            elementzdjecia.classList.add('input-warning');
            formIsValid = false; // Ustawiamy, że formularz jest niepoprawny
    
            return;  // Zatrzymaj przesyłanie formularza
        }
    }
    
    if (opis.length === 0 || opis[0].p === "") {
        const elementopisJsonString = document.getElementById('list-container'+offerId);

        elementopisJsonString.classList.add('input-warning');
        formIsValid = false; // Ustawiamy, że formularz jest niepoprawny
        return;  // Zatrzymaj przesyłanie formularza
    } 

    // Dodawanie zdjęć jako FormData
    var formData = new FormData();
    zdjecia.forEach(file => {
        formData.append('photos[]', file);
    });

    // Dodawanie istniejących nazw zdjęć jako FormData
    oldFotos_list.forEach(url => {
        formData.append('oldPhotos[]', url);
    });

    // Dodawanie istniejących nazw zdjęć
    fotoList.childNodes.forEach(child => {
        if (child.textContent.includes('(')) {
            formData.append('allPhotos[]', child.textContent.split(' (')[0]);
        } else {
            formData.append('allPhotos[]', child.textContent);
        }
    });

    // Dodanie pozostałych danych do FormData
    formData.append('title', title);
    formData.append('typNieruchomosci', typNieruchomosci);
    formData.append('rynek', rynek);
    formData.append('lokalizacja', lokalizacja);
    formData.append('cena', cena);
    formData.append('opis', opisJsonString);
    

    formData.append('lat', lat);
    formData.append('lon', lon);
    formData.append('rokBudowy', rokBudowy);
    formData.append('stan', stan);
    formData.append('nrKW', nrKW);
    formData.append('typDomu', typDomu);
    formData.append('przeznaczenieLokalu', przeznaczenieLokalu);
    formData.append('metraz', metraz);
    formData.append('poziom', poziom);
    formData.append('liczbaPieter', liczbaPieter);
    formData.append('liczbaPokoi', liczbaPokoi);
    formData.append('techBudowy', techBudowy);
    formData.append('rodzajZabudowy', rodzajZabudowy);
    formData.append('rodzajNieruchomosci', rodzajNieruchomosci);
    formData.append('kuchnia', kuchnia);
    formData.append('dodatkoweInfo', dodatkoweInfo);
    formData.append('offerID', offerIDbox);

    // Jeżeli którykolwiek z testów nie przeszedł, nie wysyłaj formularza
    if (!formIsValid) {
        return;
    }

    // Wysyłanie formularza za pomocą AJAX (fetch API)
    fetch('/save-sell-offer', {
        method: 'POST',
        body: formData
    }).then(response => {
        // console.log('response: ', response);
        if (response.ok) {
            // alert('Oferta została pomyślnie zapisana.');
            // console.log('response: ', response);
            return response.json();
        } else {
            // console.log('xxx:', data);

            throw new Error('Problem z serwerem');
        }
    }).then(data => {
        // console.log('data:', data);
        // console.log('data.seccess:', data.success);
        if (data.success == true) {
            // console.log('xxx:', data);
            var form = document.getElementById('sellOffer_' + offerId);
            form.reset();
            window.location.href = '/estate-ads-sell';            
        } else if (data.error) {
            
        }
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
    // console.log(`Kolejność w sekcji ${sekcja}:`, kolejnosc);
    return kolejnosc;
}

function pobierzIKonsolujKolejnosc(sekcjaId) {
    const sekcja = document.getElementById(sekcjaId);
    const elementy = sekcja.querySelectorAll('div');
    const kolejnosc = Array.from(elementy).map(element => element.textContent);
    
    // console.log(`Kolejność w sekcji ${sekcjaId}:`, kolejnosc);
}

function addCustomElement(id, elementType, elementContent, manualTrigger = false) {
    var container = document.getElementById('list-container' + id);
    var buttonContainer = document.getElementById('button-container' + id) || createButtonContainer(id, container);
    var newElement;
    
    if (elementType === 'li') {
        newElement = document.createElement('input');
        newElement.type = 'text';
        newElement.className = 'form-control bg-dark custom-element mb-1';
        newElement.style.color = '#c2c2c2';
        newElement.style.border = '#6a6a6a solid 1px';
        newElement.setAttribute('data-type', elementType);
        newElement.setAttribute('placeholder', `Dodaj treść dla atrybutu <${elementType}>`);
        // 👇 Wywołaj tylko jeśli to użytkownik kliknął
        if (manualTrigger) {
            toggleButtons(false);
        }
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

    if (elementType === 'li' && !container.querySelector('.end-list-button')) {
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


function checkboxControlDisable(formId, main_id, checkboxList) {
    const form = document.getElementById('form_' + formId);
    const mainCheckbox = form.querySelector('#' + main_id);
    const checkboxElements = checkboxList.map(id => form.querySelector('#' + id));

    // Funkcja aktualizująca stan checkboxów na podstawie stanu mainCheckbox
    function updateCheckboxState() {
        checkboxElements.forEach(checkbox => {
            checkbox.disabled = mainCheckbox.checked;
        });
    }

    // Dodanie event listenera dla mainCheckbox
    mainCheckbox.addEventListener('change', updateCheckboxState);

    // Inicjalizacja stanu checkboxów na podstawie aktualnego stanu mainCheckbox
    updateCheckboxState();
}

function checkboxControlEnabled(formId, main_id, checkboxList) {
    const form = document.getElementById('form_' + formId);
    const mainCheckbox = form.querySelector('#' + main_id);
    const checkboxElements = checkboxList.map(id => form.querySelector('#' + id));

    // Funkcja aktualizująca stan checkboxów na podstawie stanu mainCheckbox
    function updateCheckboxState() {
        checkboxElements.forEach(checkbox => {
            checkbox.disabled = !mainCheckbox.checked;
        });
    }

    // Dodanie event listenera dla mainCheckbox
    mainCheckbox.addEventListener('change', updateCheckboxState);

    // Inicjalizacja stanu checkboxów na podstawie aktualnego stanu mainCheckbox
    updateCheckboxState();
}

function checkboxControlOffOther(formId, main_id, checkboxList) {
    const form = document.getElementById('form_' + formId);
    const mainCheckbox = form.querySelector('#' + main_id);
    const checkboxElements = checkboxList.map(id => form.querySelector('#' + id));

    mainCheckbox.addEventListener('change', function() {
        if (mainCheckbox.checked) {
            checkboxElements.forEach(checkbox => {
                checkbox.checked = false;
            });
        }
    });

    checkboxElements.forEach((checkbox, index) => {
        checkbox.addEventListener('change', function() {
            if (checkbox.checked) {
                mainCheckbox.checked = false;
                checkboxElements.forEach((otherCheckbox, otherIndex) => {
                    if (index !== otherIndex) {
                        otherCheckbox.checked = false;
                    }
                });
            }
        });
    });
}


function setCareerDateStart(dataPoolID, isNew=true, setDateString=null) {
    // Pobranie elementu input (pole daty)
    const dateInput = document.getElementById(dataPoolID);
    const today = new Date();
    
    // Ustaw dzisiejszą datę jako minimalną
    dateInput.setAttribute('min', today.toISOString().split('T')[0]);  // Formatowanie na YYYY-MM-DD

    if (isNew) {
        // Dla nowej oferty, ustaw jutrzejszą datę jako domyślną
        const tomorrow = new Date(today);
        tomorrow.setDate(today.getDate() + 1);
        const tomorrowStr = tomorrow.toISOString().split('T')[0];  // Formatowanie na YYYY-MM-DD
        dateInput.setAttribute('value', tomorrowStr);
    } else if (setDateString) {
        // Dla edycji, ustaw datę z bazy danych
        const setDateObe = new Date(setDateString);
        const setDateStr = setDateObe.toISOString().split('T')[0];  // Formatowanie na YYYY-MM-DD
        dateInput.setAttribute('value', setDateStr);
    }
}


function collectAndSendfbgroupsform(postId) {
    // Zbieramy treść ogłoszenia i usuwamy element z liczbą znaków
    const contentDiv = document.getElementById(`fbgroups_requirementsDescription_${postId}`);
    
    // Usuwamy div z liczbą znaków
    const charCountDiv = document.getElementById(`char_count_${postId}`);
    if (charCountDiv) {
        charCountDiv.remove();
    }

    // Zbieramy treść po usunięciu licznika znaków
    const content = contentDiv.innerText.trim();

    // Sprawdzamy, czy treść ogłoszenia nie jest pusta
    if (!content) {
        contentDiv.style.border = '2px solid red'; // Podświetlenie na czerwono
        // Znajdź element diva na podstawie dynamicznego ID
        const komunikatDiv = document.getElementById(`komunikat_z_serwera_${postId}`);
            
        // Wyświetl komunikat o błędzie w divie
        if (komunikatDiv) {
            komunikatDiv.innerHTML = '<p class="alert alert-danger" role="alert">Treść ogłoszenia nie może być pusta!</p>';
        }
        return; // Zatrzymujemy wysyłkę
    } else {
        contentDiv.style.border = ''; // Usuwamy czerwone podświetlenie, jeśli pole jest wypełnione
    }

    // Zbieramy harmonogram jako listę dat
    const scheduleDates = [];
    const scheduleItems = document.querySelectorAll(`#fbgroups_shedule_${postId} .shedule-date-details`);
    scheduleItems.forEach(item => {
        scheduleDates.push(item.textContent.trim());
    });


    // Tworzymy obiekt z danymi do wysłania
    const dataToSend = {
        post_id: postId,
        content: content,  // Treść ogłoszenia
        color_choice: document.getElementById(`color_choice_${postId}`).value,

        category: document.getElementById(`category_${postId}`).value,
        created_by: document.getElementById(`created_by_${postId}`).value,
        section: document.getElementById(`section_${postId}`).value,

        id_gallery: document.getElementById(`id_gallery_${postId}`).value,

        wznawiaj: document.getElementById(`wznawiaj_${postId}`).checked,
        schedule: scheduleDates,  // Harmonogram jako lista dat
        frequency: {
            codwatygodnie: document.getElementById(`codwatygodnie_${postId}`).checked,
            cotydzien: document.getElementById(`cotydzien_${postId}`).checked,
            coczterydni: document.getElementById(`coczterydni_${postId}`).checked,
            codwadni: document.getElementById(`codwadni_${postId}`).checked
        },
        repeats: {
            ponow2razy: document.getElementById(`ponow2razy_${postId}`).checked,
            ponow5razy: document.getElementById(`ponow5razy_${postId}`).checked,
            ponow8razy: document.getElementById(`ponow8razy_${postId}`).checked,
            ponow10razy: document.getElementById(`ponow10razy_${postId}`).checked
        }
    };

    // Wysyłanie danych AJAX
    fetch('/fb-groups-sender', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(dataToSend)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Znajdź element diva na podstawie dynamicznego ID
            const komunikatDiv = document.getElementById(`komunikat_z_serwera_${postId}`);
            
            // Wyświetl komunikat o sukcesie w divie
            if (komunikatDiv) {
                komunikatDiv.innerHTML = '<p class="alert alert-info" role="alert">Ogłoszenie zostało wysłane!</p>';
                // Odśwież stronę po 5 sekundach
                setTimeout(function() {
                    window.location.href = '/career';
                }, 5000);
            }
        } else {
            // Znajdź element diva na podstawie dynamicznego ID
            const komunikatDiv = document.getElementById(`komunikat_z_serwera_${postId}`);
            
            // Wyświetl komunikat o błędzie w divie
            if (komunikatDiv) {
                komunikatDiv.innerHTML = '<p class="alert alert-danger" role="alert">Wystąpił błąd podczas wysyłania ogłoszenia.</p>';
            }
        }
    })
    .catch((error) => {
        console.error('Błąd:', error);
        alert('Wystąpił błąd podczas wysyłania ogłoszenia.');
    });
}

function collectAndSendHiddenFBform(postId) {
    // Zbieramy treść ogłoszenia i usuwamy element z liczbą znaków
    const contentDiv = document.getElementById(`fbgroups_requirementsDescription_${postId}`);
    
    // Usuwamy div z liczbą znaków
    const charCountDiv = document.getElementById(`char_count_${postId}`);
    if (charCountDiv) {
        charCountDiv.remove();
    }

    // Zbieramy treść po usunięciu licznika znaków
    const content = contentDiv.innerText.trim();

    // Sprawdzamy, czy treść ogłoszenia nie jest pusta
    if (!content) {
        contentDiv.style.border = '2px solid red'; // Podświetlenie na czerwono
        // Znajdź element diva na podstawie dynamicznego ID
        const komunikatDiv = document.getElementById(`komunikat_z_serwera_${postId}`);
            
        // Wyświetl komunikat o błędzie w divie
        if (komunikatDiv) {
            komunikatDiv.innerHTML = '<p class="alert alert-danger" role="alert">Treść ogłoszenia nie może być pusta!</p>';
        }
        return; // Zatrzymujemy wysyłkę
    } else {
        contentDiv.style.border = ''; // Usuwamy czerwone podświetlenie, jeśli pole jest wypełnione
    }

    // Zbieramy harmonogram jako listę dat
    const scheduleDates = [];
    const scheduleItems = document.querySelectorAll(`#fbgroups_shedule_${postId} .shedule-date-details`);
    scheduleItems.forEach(item => {
        scheduleDates.push(item.textContent.trim());
    });

    // Tworzymy obiekt z danymi do wysłania
    const dataToSend = {
        post_id: postId,
        content: content,  // Treść ogłoszenia
        color_choice: document.getElementById(`color_choice_${postId}`).value,

        category: document.getElementById(`category_${postId}`).value,
        created_by: document.getElementById(`created_by_${postId}`).value,
        section: document.getElementById(`section_${postId}`).value,

        id_gallery: document.getElementById(`id_gallery_${postId}`).value,

        wznawiaj: document.getElementById(`wznawiaj_${postId}`).checked,
        schedule: scheduleDates,  // Harmonogram jako lista dat
        frequency: {
            codwatygodnie: document.getElementById(`codwatygodnie_${postId}`).checked,
            cotydzien: document.getElementById(`cotydzien_${postId}`).checked,
            coczterydni: document.getElementById(`coczterydni_${postId}`).checked,
            codwadni: document.getElementById(`codwadni_${postId}`).checked
        },
        repeats: {
            ponow2razy: document.getElementById(`ponow2razy_${postId}`).checked,
            ponow5razy: document.getElementById(`ponow5razy_${postId}`).checked,
            ponow8razy: document.getElementById(`ponow8razy_${postId}`).checked,
            ponow10razy: document.getElementById(`ponow10razy_${postId}`).checked
        }
    };
    // console.log('dataToSend', dataToSend);
    // Wysyłanie danych AJAX
    fetch('/fb-groups-sender', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(dataToSend)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Znajdź element diva na podstawie dynamicznego ID
            const komunikatDiv = document.getElementById(`komunikat_z_serwera_${postId}`);
            
            // Wyświetl komunikat o sukcesie w divie
            if (komunikatDiv) {
                komunikatDiv.innerHTML = '<p class="alert alert-info" role="alert">Ogłoszenie zostało wysłane!</p>';
                // Odśwież stronę po 5 sekundach
                setTimeout(function() {
                    window.location.href = '/hidden-campaigns';
                }, 5000);
            }
        } else {
            // Znajdź element diva na podstawie dynamicznego ID
            const komunikatDiv = document.getElementById(`komunikat_z_serwera_${postId}`);
            
            // Wyświetl komunikat o błędzie w divie
            if (komunikatDiv) {
                komunikatDiv.innerHTML = '<p class="alert alert-danger" role="alert">Wystąpił błąd podczas wysyłania ogłoszenia.</p>';
            }
        }
    })
    .catch((error) => {
        console.error('Błąd:', error);
        alert('Wystąpił błąd podczas wysyłania ogłoszenia.');
    });
}

function collectAndSendfbgroupsformestateAdsRent(postId) {
    // Zbieramy treść ogłoszenia i usuwamy element z liczbą znaków
    const contentDiv = document.getElementById(`fbgroups_estateAdsRentDescription_${postId}`);
    
    // Usuwamy div z liczbą znaków
    const charCountDiv = document.getElementById(`char_count_${postId}`);
    if (charCountDiv) {
        charCountDiv.remove();
    }

    // Zbieramy treść po usunięciu licznika znaków
    const content = contentDiv.innerText.trim();

    // Sprawdzamy, czy treść ogłoszenia nie jest pusta
    if (!content) {
        contentDiv.style.border = '2px solid red'; // Podświetlenie na czerwono
        // Znajdź element diva na podstawie dynamicznego ID
        const komunikatDiv = document.getElementById(`komunikat_z_serwera_${postId}`);
            
        // Wyświetl komunikat o błędzie w divie
        if (komunikatDiv) {
            komunikatDiv.innerHTML = '<p class="alert alert-danger" role="alert">Treść ogłoszenia nie może być pusta!</p>';
        }
        return; // Zatrzymujemy wysyłkę
    } else {
        contentDiv.style.border = ''; // Usuwamy czerwone podświetlenie, jeśli pole jest wypełnione
    }

    // Zbieramy harmonogram jako listę dat
    const scheduleDates = [];
    const scheduleItems = document.querySelectorAll(`#fbgroups_shedule_${postId} .shedule-date-details`);
    scheduleItems.forEach(item => {
        scheduleDates.push(item.textContent.trim());
    });

    // Tworzymy obiekt z danymi do wysłania
    const dataToSend = {
        post_id: postId,
        content: content,  // Treść ogłoszenia
        color_choice: document.getElementById(`color_choice_${postId}`).value,

        category: document.getElementById(`category_${postId}`).value,
        created_by: document.getElementById(`created_by_${postId}`).value,
        section: document.getElementById(`section_${postId}`).value,

        id_gallery: document.getElementById(`id_gallery_${postId}`).value,

        wznawiaj: document.getElementById(`wznawiaj_${postId}`).checked,
        schedule: scheduleDates,  // Harmonogram jako lista dat
        frequency: {
            codwatygodnie: document.getElementById(`codwatygodnie_${postId}`).checked,
            cotydzien: document.getElementById(`cotydzien_${postId}`).checked,
            coczterydni: document.getElementById(`coczterydni_${postId}`).checked,
            codwadni: document.getElementById(`codwadni_${postId}`).checked
        },
        repeats: {
            ponow2razy: document.getElementById(`ponow2razy_${postId}`).checked,
            ponow5razy: document.getElementById(`ponow5razy_${postId}`).checked,
            ponow8razy: document.getElementById(`ponow8razy_${postId}`).checked,
            ponow10razy: document.getElementById(`ponow10razy_${postId}`).checked
        }
    };

    // Wysyłanie danych AJAX
    fetch('/fb-groups-sender', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(dataToSend)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Znajdź element diva na podstawie dynamicznego ID
            const komunikatDiv = document.getElementById(`komunikat_z_serwera_${postId}`);
            
            // Wyświetl komunikat o sukcesie w divie
            if (komunikatDiv) {
                komunikatDiv.innerHTML = '<p class="alert alert-info" role="alert">Ogłoszenie zostało wysłane!</p>';
                // Odśwież stronę po 5 sekundach
                setTimeout(function() {
                    window.location.href = '/estate-ads-rent';
                }, 5000);
            }
        } else {
            // Znajdź element diva na podstawie dynamicznego ID
            const komunikatDiv = document.getElementById(`komunikat_z_serwera_${postId}`);
            
            // Wyświetl komunikat o błędzie w divie
            if (komunikatDiv) {
                komunikatDiv.innerHTML = '<p class="alert alert-danger" role="alert">Wystąpił błąd podczas wysyłania ogłoszenia.</p>';
            }
        }
    })
    .catch((error) => {
        console.error('Błąd:', error);
        alert('Wystąpił błąd podczas wysyłania ogłoszenia.');
    });
}

function collectAndSendfbgroupsformestateAdsSell(postId) {
    // Zbieramy treść ogłoszenia i usuwamy element z liczbą znaków
    const contentDiv = document.getElementById(`fbgroups_estateAdsSellDescription_${postId}`);
    
    // Usuwamy div z liczbą znaków
    const charCountDiv = document.getElementById(`char_count_${postId}`);
    if (charCountDiv) {
        charCountDiv.remove();
    }

    // Zbieramy treść po usunięciu licznika znaków
    const content = contentDiv.innerText.trim();

    // Sprawdzamy, czy treść ogłoszenia nie jest pusta
    if (!content) {
        contentDiv.style.border = '2px solid red'; // Podświetlenie na czerwono
        // Znajdź element diva na podstawie dynamicznego ID
        const komunikatDiv = document.getElementById(`komunikat_z_serwera_${postId}`);
            
        // Wyświetl komunikat o błędzie w divie
        if (komunikatDiv) {
            komunikatDiv.innerHTML = '<p class="alert alert-danger" role="alert">Treść ogłoszenia nie może być pusta!</p>';
        }
        return; // Zatrzymujemy wysyłkę
    } else {
        contentDiv.style.border = ''; // Usuwamy czerwone podświetlenie, jeśli pole jest wypełnione
    }

    // Zbieramy harmonogram jako listę dat
    const scheduleDates = [];
    const scheduleItems = document.querySelectorAll(`#fbgroups_shedule_${postId} .shedule-date-details`);
    scheduleItems.forEach(item => {
        scheduleDates.push(item.textContent.trim());
    });

    // Tworzymy obiekt z danymi do wysłania
    const dataToSend = {
        post_id: postId,
        content: content,  // Treść ogłoszenia
        color_choice: document.getElementById(`color_choice_${postId}`).value,

        category: document.getElementById(`category_${postId}`).value,
        created_by: document.getElementById(`created_by_${postId}`).value,
        section: document.getElementById(`section_${postId}`).value,

        id_gallery: document.getElementById(`id_gallery_${postId}`).value,

        wznawiaj: document.getElementById(`wznawiaj_${postId}`).checked,
        schedule: scheduleDates,  // Harmonogram jako lista dat
        frequency: {
            codwatygodnie: document.getElementById(`codwatygodnie_${postId}`).checked,
            cotydzien: document.getElementById(`cotydzien_${postId}`).checked,
            coczterydni: document.getElementById(`coczterydni_${postId}`).checked,
            codwadni: document.getElementById(`codwadni_${postId}`).checked
        },
        repeats: {
            ponow2razy: document.getElementById(`ponow2razy_${postId}`).checked,
            ponow5razy: document.getElementById(`ponow5razy_${postId}`).checked,
            ponow8razy: document.getElementById(`ponow8razy_${postId}`).checked,
            ponow10razy: document.getElementById(`ponow10razy_${postId}`).checked
        }
    };

    // Wysyłanie danych AJAX
    fetch('/fb-groups-sender', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(dataToSend)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Znajdź element diva na podstawie dynamicznego ID
            const komunikatDiv = document.getElementById(`komunikat_z_serwera_${postId}`);
            
            // Wyświetl komunikat o sukcesie w divie
            if (komunikatDiv) {
                komunikatDiv.innerHTML = '<p class="alert alert-info" role="alert">Ogłoszenie zostało wysłane!</p>';
                // Odśwież stronę po 5 sekundach
                setTimeout(function() {
                    window.location.href = '/estate-ads-sell';
                }, 5000);
            }
        } else {
            // Znajdź element diva na podstawie dynamicznego ID
            const komunikatDiv = document.getElementById(`komunikat_z_serwera_${postId}`);
            
            // Wyświetl komunikat o błędzie w divie
            if (komunikatDiv) {
                komunikatDiv.innerHTML = '<p class="alert alert-danger" role="alert">Wystąpił błąd podczas wysyłania ogłoszenia.</p>';
            }
        }
    })
    .catch((error) => {
        console.error('Błąd:', error);
        alert('Wystąpił błąd podczas wysyłania ogłoszenia.');
    });
}