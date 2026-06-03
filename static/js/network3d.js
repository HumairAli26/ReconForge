// network3d.js
// ------------
// Controls the Three.js 3D network visualization for the ReconForge dashboard.

let scene, camera, renderer, controls;
let nodes = []; // Holds node meshes
let links = []; // Holds link lines
let raycaster, mouse;
let selectedNode = null;
let container = document.getElementById("three-canvas-holder");

// Color maps
const colors = {
    gateway: 0x06b6d4, // Cyan
    clean: 0x10b981,   // Emerald
    vulnerable: 0xf59e0b, // Amber
    exploited: 0xef4444, // Red
    selected: 0xd946ef,  // Magenta
    link: 0x6366f1      // Indigo
};

function init3D() {
    // Scene setup
    scene = new THREE.Scene();
    scene.background = new THREE.Color(0x02040a);

    // Camera
    camera = new THREE.PerspectiveCamera(60, container.clientWidth / container.clientHeight, 0.1, 1000);
    camera.position.set(0, 40, 80);

    // Renderer
    renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setSize(container.clientWidth, container.clientHeight);
    container.appendChild(renderer.domElement);

    // Controls
    controls = new THREE.OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.05;
    controls.maxDistance = 200;
    controls.minDistance = 10;

    // Lights
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.4);
    scene.add(ambientLight);

    const pointLight = new THREE.PointLight(0xffffff, 0.8, 200);
    pointLight.position.set(20, 50, 20);
    scene.add(pointLight);

    // Raycaster for mouse picking
    raycaster = new THREE.Raycaster();
    mouse = new THREE.Vector2();

    // Event listeners
    window.addEventListener("resize", onWindowResize);
    renderer.domElement.addEventListener("click", onDocumentMouseDown);

    // Initial gateway node
    createGateway();

    // Start animation loop
    animate();
}

function createGateway() {
    const geo = new THREE.SphereGeometry(3, 32, 32);
    const mat = new THREE.MeshPhongMaterial({
        color: colors.gateway,
        emissive: colors.gateway,
        emissiveIntensity: 0.2,
        shininess: 80
    });
    const mesh = new THREE.Mesh(geo, mat);
    mesh.position.set(0, 0, 0);
    mesh.userData = {
        ip: "Gateway",
        mac: "N/A",
        hostname: "Router",
        vendor: "Gateway",
        device_type: "Network Device",
        risk: "Clean",
        open_ports: [],
        vulns: []
    };
    scene.add(mesh);
    nodes.push(mesh);
}

function updateNetworkTopology(devices) {
    // Clear old devices (keep gateway)
    nodes.slice(1).forEach(node => scene.remove(node));
    links.forEach(link => scene.remove(link));
    nodes = [nodes[0]];
    links = [];

    // Position devices in circle around gateway
    const radius = 25;
    const count = devices.length;

    devices.forEach((dev, i) => {
        const angle = (i / count) * Math.PI * 2;
        const x = Math.cos(angle) * radius;
        const z = Math.sin(angle) * radius;
        const y = (Math.random() - 0.5) * 8; // Slight variance in height

        // Determine node color
        let col = colors.clean;
        if (dev.exploited) {
            col = colors.exploited;
        } else if (dev.vulns && dev.vulns.length > 0) {
            col = colors.vulnerable;
        }

        const geo = new THREE.SphereGeometry(2, 32, 32);
        const mat = new THREE.MeshPhongMaterial({
            color: col,
            shininess: 60
        });
        const mesh = new THREE.Mesh(geo, mat);
        mesh.position.set(x, y, z);
        mesh.userData = dev; // Bind API device object to mesh data

        scene.add(mesh);
        nodes.push(mesh);

        // Draw connection link to gateway
        const points = [];
        points.push(new THREE.Vector3(0, 0, 0));
        points.push(new THREE.Vector3(x, y, z));
        const lineGeo = new THREE.BufferGeometry().setFromPoints(points);
        const lineMat = new THREE.LineBasicMaterial({
            color: colors.link,
            transparent: true,
            opacity: 0.4
        });
        const line = new THREE.Line(lineGeo, lineMat);
        scene.add(line);
        links.push(line);
    });
}

function onDocumentMouseDown(event) {
    event.preventDefault();

    // Calculate mouse position in normalized device coordinates
    const rect = renderer.domElement.getBoundingClientRect();
    mouse.x = ((event.clientX - rect.left) / container.clientWidth) * 2 - 1;
    mouse.y = -((event.clientY - rect.top) / container.clientHeight) * 2 + 1;

    raycaster.setFromCamera(mouse, camera);

    // Pick nodes
    const intersects = raycaster.intersectObjects(nodes);

    if (intersects.length > 0) {
        const clickedMesh = intersects[0].object;

        // Reset previous selection color
        if (selectedNode) {
            let col = colors.clean;
            if (selectedNode.userData.ip === "Gateway") {
                col = colors.gateway;
            } else if (selectedNode.userData.exploited) {
                col = colors.exploited;
            } else if (selectedNode.userData.vulns && selectedNode.userData.vulns.length > 0) {
                col = colors.vulnerable;
            }
            selectedNode.material.color.setHex(col);
        }

        selectedNode = clickedMesh;
        selectedNode.material.color.setHex(colors.selected);

        // Show details in UI
        if (typeof window.showHostDetails === "function") {
            window.showHostDetails(selectedNode.userData);
        }
    }
}

function onWindowResize() {
    camera.aspect = container.clientWidth / container.clientHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(container.clientWidth, container.clientHeight);
}

function animate() {
    requestAnimationFrame(animate);

    // Slowly rotate topology
    scene.rotation.y += 0.001;

    // Pulsing animation for vulnerable/exploited nodes
    const time = Date.now() * 0.003;
    nodes.forEach(node => {
        if (node.userData.ip === "Gateway") return;

        // Pulse scale
        if (node.userData.exploited || (node.userData.vulns && node.userData.vulns.length > 0)) {
            const scale = 1.0 + Math.sin(time) * 0.12;
            node.scale.set(scale, scale, scale);
        } else {
            node.scale.set(1.0, 1.0, 1.0);
        }
    });

    controls.update();
    renderer.render(scene, camera);
}

// Initialise
init3D();
