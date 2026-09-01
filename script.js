/* =========================================
   VAULTX PASSWORD MANAGER
   Vanilla JavaScript + Web Crypto API

   Encryption:
   PBKDF2 -> AES-256-GCM

   Storage:
   localStorage contains ONLY encrypted vault data.
========================================= */


/* =========================================
   CONFIGURATION
========================================= */

const STORAGE_KEY = "vaultx_encrypted_vault";

const AUTO_LOCK_TIME = 5 * 60 * 1000;

const PBKDF2_ITERATIONS = 600000;

const AES_KEY_LENGTH = 256;

const SALT_LENGTH = 16;

const IV_LENGTH = 12;


/* =========================================
   APPLICATION STATE
========================================= */

let vault = [];

let masterPassword = null;

let currentAccountId = null;

let currentFilter = "All";

let currentPage = "vault";

let inactivityTimer = null;

let lastActivity = Date.now();


/* =========================================
   DOM
========================================= */

const $ = (selector) =>
    document.querySelector(selector);

const $$ = (selector) =>
    document.querySelectorAll(selector);


/* =========================================
   INITIALIZATION
========================================= */

document.addEventListener("DOMContentLoaded", () => {

    initializeApp();

});


async function initializeApp() {

    setupEventListeners();

    updateLockScreen();

    updatePasswordStrength("");

}


/* =========================================
   STORAGE
========================================= */

function hasVault() {

    return Boolean(
        localStorage.getItem(STORAGE_KEY)
    );

}


/* =========================================
   WEB CRYPTO
========================================= */

const encoder = new TextEncoder();
const decoder = new TextDecoder();


function bytesToBase64(bytes) {

    let binary = "";

    const chunkSize = 0x8000;

    for (
        let i = 0;
        i < bytes.length;
        i += chunkSize
    ) {

        binary += String.fromCharCode(
            ...bytes.subarray(
                i,
                i + chunkSize
            )
        );

    }

    return btoa(binary);

}


function base64ToBytes(base64) {

    const binary = atob(base64);

    const bytes = new Uint8Array(
        binary.length
    );

    for (
        let i = 0;
        i < binary.length;
        i++
    ) {

        bytes[i] = binary.charCodeAt(i);

    }

    return bytes;

}


async function deriveKey(
    password,
    salt
) {

    const passwordKey =
        await crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            {
                name: "PBKDF2"
            },
            false,
            ["deriveKey"]
        );


    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },
        passwordKey,
        {
            name: "AES-GCM",
            length: AES_KEY_LENGTH
        },
        false,
        [
            "encrypt",
            "decrypt"
        ]
    );

}


async function encryptVault(
    data,
    password
) {

    const salt =
        crypto.getRandomValues(
            new Uint8Array(SALT_LENGTH)
        );

    const iv =
        crypto.getRandomValues(
            new Uint8Array(IV_LENGTH)
        );


    const key =
        await deriveKey(
            password,
            salt
        );


    const plaintext =
        encoder.encode(
            JSON.stringify(data)
        );


    const ciphertext =
        await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv
            },
            key,
            plaintext
        );


    return {

        version: 1,

        algorithm: "AES-256-GCM",

        kdf: "PBKDF2-SHA256",

        iterations:
            PBKDF2_ITERATIONS,

        salt:
            bytesToBase64(salt),

        iv:
            bytesToBase64(iv),

        data:
            bytesToBase64(
                new Uint8Array(ciphertext)
            ),

        createdAt:
            new Date().toISOString()

    };

}


async function decryptVault(
    payload,
    password
) {

    if (
        !payload ||
        !payload.salt ||
        !payload.iv ||
        !payload.data
    ) {

        throw new Error(
            "Invalid encrypted vault."
        );

    }


    const salt =
        base64ToBytes(
            payload.salt
        );

    const iv =
        base64ToBytes(
            payload.iv
        );

    const ciphertext =
        base64ToBytes(
            payload.data
        );


    const key =
        await deriveKey(
            password,
            salt
        );


    let plaintext;


    try {

        plaintext =
            await crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv
                },
                key,
                ciphertext
            );

    } catch {

        throw new Error(
            "Incorrect master password or corrupted vault."
        );

    }


    const parsed =
        JSON.parse(
            decoder.decode(plaintext)
        );


    if (!Array.isArray(parsed)) {

        throw new Error(
            "Invalid vault structure."
        );

    }


    return parsed;

}


/* =========================================
   VAULT SAVE
========================================= */

async function saveVault() {

    if (!masterPassword) {

        throw new Error(
            "Vault is locked."
        );

    }


    const encrypted =
        await encryptVault(
            vault,
            masterPassword
        );


    localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify(encrypted)
    );

}


/* =========================================
   LOCK SCREEN
========================================= */

function updateLockScreen() {

    const existing =
        hasVault();


    if (existing) {

        $("#lockTitle").textContent =
            "Unlock Your Vault";

        $("#lockDescription").textContent =
            "Enter your master password to decrypt your local vault.";

        $("#confirmPasswordGroup")
            .classList
            .add("hidden");

        $("#masterButtonText").textContent =
            "Unlock Vault";

    } else {

        $("#lockTitle").textContent =
            "Create Your Master Password";

        $("#lockDescription").textContent =
            "Your master password protects your encrypted vault.";

        $("#confirmPasswordGroup")
            .classList
            .remove("hidden");

        $("#masterButtonText").textContent =
            "Create Vault";

    }

}


async function handleMasterPassword(event) {

    event.preventDefault();


    const password =
        $("#masterPassword").value;

    const confirm =
        $("#confirmPassword").value;


    if (password.length < 12) {

        showToast(
            "Use a master password with at least 12 characters.",
            "warning"
        );

        return;

    }


    if (!hasVault()) {

        if (password !== confirm) {

            showToast(
                "Master passwords do not match.",
                "warning"
            );

            return;

        }


        try {

            vault = [];

            masterPassword = password;

            await saveVault();

            unlockApplication();

            showToast(
                "Encrypted vault created successfully.",
                "success"
            );

        } catch (error) {

            console.error(error);

            masterPassword = null;

            showToast(
                "Could not create vault.",
                "warning"
            );

        }

    } else {

        try {

            const encrypted =
                JSON.parse(
                    localStorage.getItem(
                        STORAGE_KEY
                    )
                );


            const decrypted =
                await decryptVault(
                    encrypted,
                    password
                );


            vault = decrypted;

            masterPassword = password;

            unlockApplication();

            showToast(
                "Vault unlocked.",
                "success"
            );

        } catch (error) {

            console.error(error);

            showToast(
                "Incorrect master password.",
                "warning"
            );

            $("#masterPassword").value = "";

        }

    }

}


/* =========================================
   UNLOCK / LOCK
========================================= */

function unlockApplication() {

    $("#lockScreen")
        .classList
        .add("hidden");

    $("#app")
        .classList
        .remove("hidden");

    $("#masterPasswordForm").reset();

    updateDashboard();

    resetInactivityTimer();

}


function lockApplication() {

    clearTimeout(inactivityTimer);

    inactivityTimer = null;


    /*
        Remove decrypted sensitive data
        from the active JavaScript state.
    */

    vault = [];

    masterPassword = null;

    currentAccountId = null;


    $("#app")
        .classList
        .add("hidden");

    $("#lockScreen")
        .classList
        .remove("hidden");


    updateLockScreen();

    $("#masterPassword").value = "";

    $("#confirmPassword").value = "";

}


/* =========================================
   AUTO LOCK
========================================= */

function resetInactivityTimer() {

    if (!masterPassword) {
        return;
    }


    lastActivity = Date.now();


    clearTimeout(
        inactivityTimer
    );


    inactivityTimer =
        setTimeout(
            () => {

                showToast(
                    "Vault locked due to inactivity.",
                    "warning"
                );

                lockApplication();

            },
            AUTO_LOCK_TIME
        );

}


function registerActivity() {

    if (!masterPassword) {
        return;
    }


    const now = Date.now();


    if (
        now - lastActivity >
        5000
    ) {

        resetInactivityTimer();

    }

}


[
    "mousemove",
    "keydown",
    "click",
    "scroll",
    "touchstart"
].forEach(eventName => {

    document.addEventListener(
        eventName,
        registerActivity,
        {
            passive: true
        }
    );

});


/* =========================================
   ACCOUNT MANAGEMENT
========================================= */

async function handleAccountSubmit(event) {

    event.preventDefault();


    const id =
        $("#accountId").value;


    const account = {

        id:
            id ||
            crypto.randomUUID(),

        title:
            $("#title").value.trim(),

        website:
            $("#website").value.trim(),

        username:
            $("#username").value.trim(),

        password:
            $("#password").value,

        category:
            $("#category").value,

        favorite:
            false,

        updatedAt:
            new Date().toISOString()

    };


    if (!account.title) {

        showToast(
            "Enter a service name.",
            "warning"
        );

        return;

    }


    if (!account.username) {

        showToast(
            "Enter a username or email.",
            "warning"
        );

        return;

    }


    if (!account.password) {

        showToast(
            "Enter a password.",
            "warning"
        );

        return;

    }


    const existingIndex =
        vault.findIndex(
            item => item.id === id
        );


    if (existingIndex !== -1) {

        account.favorite =
            vault[existingIndex].favorite;

        vault[existingIndex] =
            account;

    } else {

        vault.unshift(account);

    }


    try {

        await saveVault();

        closeModal("accountModal");

        updateDashboard();

        showToast(
            id
                ? "Account updated."
                : "Account encrypted and saved.",
            "success"
        );

    } catch (error) {

        console.error(error);

        showToast(
            "Could not save account.",
            "warning"
        );

    }

}


/* =========================================
   OPEN ADD MODAL
========================================= */

function openAddModal() {

    $("#accountForm").reset();

    $("#accountId").value = "";

    $("#modalTitle").textContent =
        "Add New Account";

    openModal("accountModal");

    setTimeout(
        () => $("#title").focus(),
        100
    );

}


/* =========================================
   EDIT ACCOUNT
========================================= */

function editAccount(id) {

    const account =
        vault.find(
            item => item.id === id
        );


    if (!account) {
        return;
    }


    $("#accountId").value =
        account.id;

    $("#title").value =
        account.title;

    $("#website").value =
        account.website || "";

    $("#username").value =
        account.username;

    $("#password").value =
        account.password;

    $("#category").value =
        account.category;


    $("#modalTitle").textContent =
        "Edit Account";


    closeModal("viewModal");

    openModal("accountModal");

}


/* =========================================
   DELETE
========================================= */

function requestDelete(id) {

    currentAccountId = id;

    openModal("deleteModal");

}


async function deleteAccount() {

    if (!currentAccountId) {
        return;
    }


    vault =
        vault.filter(
            item =>
                item.id !== currentAccountId
        );


    try {

        await saveVault();

        closeModal("deleteModal");

        closeModal("viewModal");

        updateDashboard();

        currentAccountId = null;

        showToast(
            "Account deleted.",
            "success"
        );

    } catch (error) {

        console.error(error);

        showToast(
            "Could not delete account.",
            "warning"
        );

    }

}


/* =========================================
   FAVORITES
========================================= */

async function toggleFavorite(id) {

    const account =
        vault.find(
            item => item.id === id
        );


    if (!account) {
        return;
    }


    account.favorite =
        !account.favorite;

    account.updatedAt =
        new Date().toISOString();


    await saveVault();

    updateDashboard();


    showToast(
        account.favorite
            ? "Added to favorites."
            : "Removed from favorites.",
        "success"
    );

}


/* =========================================
   VIEW ACCOUNT
========================================= */

function viewAccount(id) {

    const account =
        vault.find(
            item => item.id === id
        );


    if (!account) {
        return;
    }


    currentAccountId = id;


    $("#detailTitle").textContent =
        account.title;

    $("#detailCategory").textContent =
        account.category.toUpperCase();

    $("#detailUsername").textContent =
        account.username;

    $("#detailPassword").textContent =
        "••••••••••••";

    $("#detailPassword")
        .dataset.visible = "false";


    const icon =
        getServiceIcon(
            account.title
        );

    $("#detailIcon").textContent =
        icon;


    const categoryBadge =
        $("#detailCategoryBadge");

    categoryBadge.textContent =
        account.category;


    if (account.website) {

        $("#detailWebsite").textContent =
            account.website;

        $("#detailWebsite").href =
            normalizeURL(
                account.website
            );

    } else {

        $("#detailWebsite").textContent =
            "No website";

        $("#detailWebsite").removeAttribute(
            "href"
        );

    }


    $("#detailEdit").onclick =
        () => editAccount(id);

    $("#detailDelete").onclick =
        () => requestDelete(id);


    openModal("viewModal");

}


/* =========================================
   PASSWORD GENERATOR
========================================= */

function generateStrongPassword(length = 20) {

    const uppercase =
        "ABCDEFGHJKLMNPQRSTUVWXYZ";

    const lowercase =
        "abcdefghijkmnopqrstuvwxyz";

    const numbers =
        "23456789";

    const symbols =
        "!@#$%^&*()-_=+[]{}";

    const all =
        uppercase +
        lowercase +
        numbers +
        symbols;


    const randomChar =
        chars =>
            chars[
                crypto.getRandomValues(
                    new Uint32Array(1)
                )[0] %
                chars.length
            ];


    let password = "";

    password += randomChar(uppercase);
    password += randomChar(lowercase);
    password += randomChar(numbers);
    password += randomChar(symbols);


    while (
        password.length <
        length
    ) {

        password +=
            randomChar(all);

    }


    /*
        Fisher-Yates shuffle using
        cryptographically secure randomness.
    */

    const array =
        password.split("");


    for (
        let i = array.length - 1;
        i > 0;
        i--
    ) {

        const random =
            crypto.getRandomValues(
                new Uint32Array(1)
            )[0];

        const j =
            random %
            (i + 1);


        [
            array[i],
            array[j]
        ] =
        [
            array[j],
            array[i]
        ];

    }


    return array.join("");

}


function useGeneratedPassword() {

    const password =
        generateStrongPassword(20);


    $("#password").value =
        password;


    $("#password").type =
        "text";


    showToast(
        "Strong password generated.",
        "success"
    );

}


/* =========================================
   SEARCH / FILTER
========================================= */

function getFilteredAccounts() {

    const search =
        $("#searchInput")
            .value
            .trim()
            .toLowerCase();


    let accounts =
        [...vault];


    if (
        currentPage ===
        "favorites"
    ) {

        accounts =
            accounts.filter(
                item => item.favorite
            );

    }


    if (
        currentPage ===
        "categories"
    ) {

        if (currentFilter === "All") {

            // Keep all accounts.

        }

    }


    if (
        currentFilter !==
        "All"
    ) {

        accounts =
            accounts.filter(
                item =>
                    item.category ===
                    currentFilter
            );

    }


    if (search) {

        accounts =
            accounts.filter(
                item =>
                    item.title
                        .toLowerCase()
                        .includes(search) ||

                    item.username
                        .toLowerCase()
                        .includes(search)
            );

    }


    return sortAccounts(
        accounts
    );

}


function sortAccounts(accounts) {

    const sort =
        $("#sortSelect").value;


    if (sort === "name") {

        return accounts.sort(
            (a, b) =>
                a.title.localeCompare(
                    b.title
                )
        );

    }


    if (sort === "category") {

        return accounts.sort(
            (a, b) =>
                a.category.localeCompare(
                    b.category
                )
        );

    }


    return accounts.sort(
        (a, b) =>
            new Date(b.updatedAt || 0) -
            new Date(a.updatedAt || 0)
    );

}


/* =========================================
   RENDER DASHBOARD
========================================= */

function updateDashboard() {

    updateStats();

    updateCategoryCounts();

    renderAccounts();

}


function updateStats() {

    $("#totalAccounts").textContent =
        vault.length;

    $("#favoriteCount").textContent =
        vault.filter(
            item => item.favorite
        ).length;

}


function updateCategoryCounts() {

    const categories = [
        "All",
        "Social",
        "Work",
        "Finance",
        "Shopping",
        "Other"
    ];


    categories.forEach(category => {

        const element =
            $(`#${category.toLowerCase()}Count`);


        if (element) {

            element.textContent =
                category === "All"
                    ? vault.length
                    : vault.filter(
                        item =>
                            item.category ===
                            category
                    ).length;

        }

    });

}


function renderAccounts() {

    const list =
        $("#accountList");

    const empty =
        $("#emptyState");


    const accounts =
        getFilteredAccounts();


    list.innerHTML = "";


    if (!accounts.length) {

        empty.classList.remove(
            "hidden"
        );

        return;

    }


    empty.classList.add(
        "hidden"
    );


    accounts.forEach(account => {

        list.appendChild(
            createAccountCard(account)
        );

    });

}


function createAccountCard(account) {

    const card =
        document.createElement("article");

    card.className =
        "account-card";


    const icon =
        getServiceIcon(
            account.title
        );


    card.innerHTML = `

        <div
            class="account-info"
            data-view="${escapeAttribute(account.id)}"
        >

            <div class="service-icon">
                ${escapeHTML(icon)}
            </div>

            <div class="account-name">

                <strong>
                    ${escapeHTML(account.title)}
                </strong>

                <span>
                    ${escapeHTML(
                        account.website ||
                        account.category
                    )}
                </span>

            </div>

        </div>


        <div class="account-username">
            ${escapeHTML(account.username)}
        </div>


        <div>

            <span class="masked-password">
                ••••••••••••
            </span>

        </div>


        <div class="card-actions">

            <button
                class="card-action favorite
                    ${account.favorite ? "active" : ""}"
                data-action="favorite"
                data-id="${escapeAttribute(account.id)}"
                title="Favorite"
            >
                ★
            </button>

            <button
                class="card-action"
                data-action="view"
                data-id="${escapeAttribute(account.id)}"
                title="View"
            >
                👁
            </button>

            <button
                class="card-action"
                data-action="edit"
                data-id="${escapeAttribute(account.id)}"
                title="Edit"
            >
                ✎
            </button>

            <button
                class="card-action"
                data-action="delete"
                data-id="${escapeAttribute(account.id)}"
                title="Delete"
            >
                🗑
            </button>

        </div>

    `;


    return card;

}


/* =========================================
   EVENT DELEGATION
========================================= */

$("#accountList").addEventListener(
    "click",
    event => {

        const button =
            event.target.closest(
                "[data-action]"
            );


        const info =
            event.target.closest(
                "[data-view]"
            );


        if (
            !button &&
            info
        ) {

            viewAccount(
                info.dataset.view
            );

            return;

        }


        if (!button) {
            return;
        }


        const id =
            button.dataset.id;

        const action =
            button.dataset.action;


        if (action === "view") {

            viewAccount(id);

        }

        else if (
            action === "edit"
        ) {

            editAccount(id);

        }

        else if (
            action === "delete"
        ) {

            requestDelete(id);

        }

        else if (
            action === "favorite"
        ) {

            toggleFavorite(id);

        }

    }
);


/* =========================================
   CATEGORY FILTERS
========================================= */

function setFilter(filter) {

    currentFilter = filter;


    $$(".filter-tag")
        .forEach(button => {

            button.classList.toggle(
                "active",
                button.dataset.filter ===
                filter
            );

        });


    $$(".category-side")
        .forEach(button => {

            button.classList.toggle(
                "active",
                button.dataset.category ===
                filter
            );

        });


    renderAccounts();

}


/* =========================================
   PAGE NAVIGATION
========================================= */

function setPage(page) {

    currentPage = page;


    $$(".nav-item")
        .forEach(item => {

            item.classList.toggle(
                "active",
                item.dataset.page ===
                page
            );

        });


    if (page === "vault") {

        $("#pageTitle").textContent =
            "Password Vault";

        currentFilter = "All";

    }

    else if (
        page === "favorites"
    ) {

        $("#pageTitle").textContent =
            "Favorite Accounts";

        currentFilter = "All";

    }

    else if (
        page === "categories"
    ) {

        $("#pageTitle").textContent =
            "Categories";

    }


    updateFilterButtons();

    renderAccounts();

}


function updateFilterButtons() {

    $$(".filter-tag")
        .forEach(button => {

            button.classList.toggle(
                "active",
                button.dataset.filter ===
                currentFilter
            );

        });

}


/* =========================================
   COPY TO CLIPBOARD
========================================= */

async function copyText(text) {

    try {

        await navigator.clipboard.writeText(
            text
        );

        showToast(
            "Copied to clipboard.",
            "success"
        );


        /*
            Automatically clear clipboard
            after 30 seconds when supported.
        */

        setTimeout(
            async () => {

                try {

                    const current =
                        await navigator.clipboard.readText();

                    if (current === text) {

                        await navigator.clipboard.writeText(
                            ""
                        );

                    }

                } catch {
                    // Browser may block clipboard read.
                }

            },
            30000
        );

    } catch {

        showToast(
            "Clipboard access was blocked.",
            "warning"
        );

    }

}


/* =========================================
   EXPORT ENCRYPTED VAULT
========================================= */

function exportVault() {

    if (!masterPassword) {
        return;
    }


    const encrypted =
        localStorage.getItem(
            STORAGE_KEY
        );


    if (!encrypted) {

        showToast(
            "No encrypted vault exists.",
            "warning"
        );

        return;

    }


    const blob =
        new Blob(
            [
                encrypted
            ],
            {
                type:
                    "application/json"
            }
        );


    const url =
        URL.createObjectURL(
            blob
        );


    const link =
        document.createElement("a");

    link.href = url;

    link.download =
        `vaultx-encrypted-${getDateStamp()}.json`;

    document.body.appendChild(link);

    link.click();

    link.remove();

    URL.revokeObjectURL(url);


    showToast(
        "Encrypted vault exported.",
        "success"
    );

}


/* =========================================
   IMPORT ENCRYPTED VAULT
========================================= */

function importVault() {

    $("#importFile").click();

}


async function handleImport(event) {

    const file =
        event.target.files[0];


    if (!file) {
        return;
    }


    try {

        const text =
            await file.text();


        const imported =
            JSON.parse(text);


        if (
            !imported ||
            imported.algorithm !==
            "AES-256-GCM" ||
            imported.kdf !==
            "PBKDF2-SHA256"
        ) {

            throw new Error(
                "Unsupported vault format."
            );

        }


        /*
            Validate the password BEFORE replacing
            the existing local vault.
        */

        const password =
            prompt(
                "Enter the master password for this imported vault:"
            );


        if (!password) {

            event.target.value = "";

            return;

        }


        const decrypted =
            await decryptVault(
                imported,
                password
            );


        /*
            Replace the current encrypted vault
            only after successful decryption.
        */

        localStorage.setItem(
            STORAGE_KEY,
            JSON.stringify(imported)
        );


        vault =
            decrypted;

        masterPassword =
            password;


        updateDashboard();

        showToast(
            "Encrypted vault imported successfully.",
            "success"
        );

    } catch (error) {

        console.error(error);

        showToast(
            error.message ||
            "Could not import vault.",
            "warning"
        );

    }


    event.target.value = "";

}


/* =========================================
   PASSWORD VISIBILITY
========================================= */

function togglePasswordInput(
    targetId
) {

    const input =
        document.getElementById(
            targetId
        );


    if (!input) {
        return;
    }


    input.type =
        input.type === "password"
            ? "text"
            : "password";

}


/* =========================================
   DETAIL PASSWORD
========================================= */

function toggleDetailPassword() {

    if (!currentAccountId) {
        return;
    }


    const account =
        vault.find(
            item =>
                item.id ===
                currentAccountId
        );


    if (!account) {
        return;
    }


    const element =
        $("#detailPassword");


    const visible =
        element.dataset.visible ===
        "true";


    if (visible) {

        element.textContent =
            "••••••••••••";

        element.dataset.visible =
            "false";

    } else {

        element.textContent =
            account.password;

        element.dataset.visible =
            "true";

    }

}


/* =========================================
   SERVICE ICON
========================================= */

function getServiceIcon(title) {

    const name =
        title.toLowerCase();


    if (name.includes("github")) {
        return "GH";
    }

    if (
        name.includes("google") ||
        name.includes("gmail")
    ) {
        return "G";
    }

    if (
        name.includes("facebook")
    ) {
        return "f";
    }

    if (
        name.includes("instagram")
    ) {
        return "◎";
    }

    if (
        name.includes("discord")
    ) {
        return "◉";
    }

    if (
        name.includes("linkedin")
    ) {
        return "in";
    }

    if (
        name.includes("youtube")
    ) {
        return "▶";
    }

    if (
        name.includes("amazon")
    ) {
        return "a";
    }

    if (
        name.includes("microsoft")
    ) {
        return "M";
    }

    if (
        name.includes("netflix")
    ) {
        return "N";
    }

    if (
        name.includes("apple")
    ) {
        return "";
    }


    return (
        title
            .trim()
            .charAt(0)
            .toUpperCase() ||
        "?"
    );

}


/* =========================================
   URL NORMALIZATION
========================================= */

function normalizeURL(url) {

    if (
        /^https?:\/\//i.test(url)
    ) {

        return url;

    }


    return `https://${url}`;

}


/* =========================================
   ESCAPING
========================================= */

function escapeHTML(value) {

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");

}


function escapeAttribute(value) {

    return escapeHTML(value);

}


/* =========================================
   PASSWORD STRENGTH
========================================= */

function updatePasswordStrength(
    password
) {

    const fill =
        $("#strengthFill");

    const text =
        $("#strengthText");


    if (!password) {

        fill.style.width =
            "0%";

        text.textContent =
            "Password strength";

        return;

    }


    let score = 0;


    if (password.length >= 12) {
        score++;
    }

    if (password.length >= 16) {
        score++;
    }

    if (/[a-z]/.test(password)) {
        score++;
    }

    if (/[A-Z]/.test(password)) {
        score++;
    }

    if (/[0-9]/.test(password)) {
        score++;
    }

    if (/[^A-Za-z0-9]/.test(password)) {
        score++;
    }


    const percentage =
        Math.min(
            100,
            score * 16.66
        );


    fill.style.width =
        `${percentage}%`;


    if (score <= 2) {

        text.textContent =
            "Weak";

    }

    else if (score <= 4) {

        text.textContent =
            "Medium";

    }

    else {

        text.textContent =
            "Strong";

    }

}


/* =========================================
   MODALS
========================================= */

function openModal(id) {

    const modal =
        document.getElementById(id);


    if (modal) {

        modal.classList.remove(
            "hidden"
        );

    }

}


function closeModal(id) {

    const modal =
        document.getElementById(id);


    if (modal) {

        modal.classList.add(
            "hidden"
        );

    }

}


/* =========================================
   TOAST
========================================= */

let toastTimeout;


function showToast(
    message,
    type = ""
) {

    const toast =
        $("#toast");


    toast.textContent =
        message;

    toast.className =
        `toast ${type}`;


    requestAnimationFrame(
        () => {

            toast.classList.add(
                "show"
            );

        }
    );


    clearTimeout(
        toastTimeout
    );


    toastTimeout =
        setTimeout(
            () => {

                toast.classList.remove(
                    "show"
                );

            },
            2800
        );

}


/* =========================================
   DATE
========================================= */

function getDateStamp() {

    return new Date()
        .toISOString()
        .slice(0, 10);

}


/* =========================================
   THEME
========================================= */

function toggleTheme() {

    document.body.classList.toggle(
        "light"
    );


    const light =
        document.body.classList.contains(
            "light"
        );


    localStorage.setItem(
        "vaultx_theme",
        light
            ? "light"
            : "dark"
    );


    $("#themeBtn").textContent =
        light
            ? "☀"
            : "☾";

}


function loadTheme() {

    const theme =
        localStorage.getItem(
            "vaultx_theme"
        );


    if (theme === "light") {

        document.body.classList.add(
            "light"
        );

        $("#themeBtn").textContent =
            "☀";

    }

}


/* =========================================
   EVENT LISTENERS
========================================= */

function setupEventListeners() {

    loadTheme();


    $("#masterPasswordForm")
        .addEventListener(
            "submit",
            handleMasterPassword
        );


    $("#masterPassword")
        .addEventListener(
            "input",
            event =>
                updatePasswordStrength(
                    event.target.value
                )
        );


    $("#addAccountBtn")
        .addEventListener(
            "click",
            openAddModal
        );


    $("#emptyAddBtn")
        .addEventListener(
            "click",
            openAddModal
        );


    $("#accountForm")
        .addEventListener(
            "submit",
            handleAccountSubmit
        );


    $("#generatePassword")
        .addEventListener(
            "click",
            useGeneratedPassword
        );


    $("#searchInput")
        .addEventListener(
            "input",
            renderAccounts
        );


    $("#sortSelect")
        .addEventListener(
            "change",
            renderAccounts
        );


    $$(".filter-tag")
        .forEach(button => {

            button.addEventListener(
                "click",
                () =>
                    setFilter(
                        button.dataset.filter
                    )
            );

        });


    $$(".category-side")
        .forEach(button => {

            button.addEventListener(
                "click",
                () => {

                    setPage("vault");

                    setFilter(
                        button.dataset.category
                    );

                }
            );

        });


    $$(".nav-item")
        .forEach(button => {

            button.addEventListener(
                "click",
                () =>
                    setPage(
                        button.dataset.page
                    )
            );

        });


    $("#lockBtn")
        .addEventListener(
            "click",
            () => {

                lockApplication();

            }
        );


    $("#quickLockBtn")
        .addEventListener(
            "click",
            () => {

                lockApplication();

            }
        );


    $("#exportBtn")
        .addEventListener(
            "click",
            exportVault
        );


    $("#importBtn")
        .addEventListener(
            "click",
            importVault
        );


    $("#importFile")
        .addEventListener(
            "change",
            handleImport
        );


    $("#confirmDelete")
        .addEventListener(
            "click",
            deleteAccount
        );


    $("#themeBtn")
        .addEventListener(
            "click",
            toggleTheme
        );


    $("#detailPasswordToggle")
        .addEventListener(
            "click",
            toggleDetailPassword
        );


    $$(".password-toggle")
        .forEach(button => {

            button.addEventListener(
                "click",
                () =>
                    togglePasswordInput(
                        button.dataset.target
                    )
            );

        });


    $$(".modal-overlay")
        .forEach(overlay => {

            overlay.addEventListener(
                "click",
                event => {

                    if (
                        event.target ===
                        overlay
                    ) {

                        overlay.classList.add(
                            "hidden"
                        );

                    }

                }
            );

        });


    $$(".modal-close, [data-close]")
        .forEach(button => {

            button.addEventListener(
                "click",
                () =>
                    closeModal(
                        button.dataset.close
                    )
            );

        });


    $("#mobileMenu")
        .addEventListener(
            "click",
            () =>
                $(".sidebar")
                    .classList
                    .add("open")
        );


    $("#mobileSidebarClose")
        .addEventListener(
            "click",
            () =>
                $(".sidebar")
                    .classList
                    .remove("open")
        );


    /*
        Keyboard shortcut:
        Ctrl + K -> Search
    */

    document.addEventListener(
        "keydown",
        event => {

            if (
                (event.ctrlKey ||
                    event.metaKey) &&
                event.key.toLowerCase() ===
                    "k"
            ) {

                event.preventDefault();

                $("#searchInput").focus();

            }


            if (
                event.key === "Escape"
            ) {

                $$(".modal-overlay")
                    .forEach(
                        modal =>
                            modal.classList.add(
                                "hidden"
                            )
                    );

            }

        }
    );


    /*
        Copy buttons inside detail modal.
    */

    document.addEventListener(
        "click",
        event => {

            const button =
                event.target.closest(
                    "[data-copy]"
                );


            if (!button) {
                return;
            }


            if (!currentAccountId) {
                return;
            }


            const account =
                vault.find(
                    item =>
                        item.id ===
                        currentAccountId
                );


            if (!account) {
                return;
            }


            const type =
                button.dataset.copy;


            if (type === "username") {

                copyText(
                    account.username
                );

            }

            else if (
                type === "password"
            ) {

                copyText(
                    account.password
                );

            }

        }
    );

}


/* =========================================
   BEFORE PAGE UNLOAD
========================================= */

/*
    Never persist plaintext vault data.
    The only persistent vault data is the
    AES-GCM encrypted payload in localStorage.
*/

window.addEventListener(
    "beforeunload",
    () => {

        vault = [];

        masterPassword = null;

    }
);