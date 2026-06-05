// network3d.js
// ------------
// Controls the Three.js 3D network visualization for the ReconForge dashboard.

let scene, camera, renderer, controls;
let nodes = []; // Holds node meshes
let links = []; // Holds link lines
let scanRingMesh = null; // Pulsing radar scan ring
let raycaster, mouse;
let selectedNode = null;
let container = document.getElementById("three-canvas-holder");

// Color maps - Hacker Cyberpunk theme colors
const colors = {
    gateway: 0x00f0ff,     // Glowing Cyan
    clean: 0x00ff66,       // Glowing Green
    vulnerable: 0xffaa00,   // Amber Warning
    exploited: 0xff0055,    // Red Critical
    selected: 0xd946ef,    // Magenta
    link: 0x00ff66,        // Link Lines
    grid: 0x003311         // Dark Green grid
};

function init3D() {
    // Scene setup
    scene = new THREE.Scene();
    scene.background = new THREE.Color(0x010206);
    scene.fog = new THREE.FogExp2(0x010206, 0.007);

    // Camera
    camera = new THREE.PerspectiveCamera(60, container.clientWidth / container.clientHeight, 0.1, 1000);
    camera.position.set(0, 35, 75);

    // Renderer
    renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setSize(container.clientWidth, container.clientHeight);
    container.appendChild(renderer.domElement);

    // Controls
    controls = new THREE.OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.05;
    controls.maxDistance = 150;
    controls.minDistance = 15;

    // Add Grid floor
    const gridHelper = new THREE.GridHelper(200, 50, 0x00ff66, 0x002208);
    gridHelper.position.y = -10;
    gridHelper.material.opacity = 0.15;
    gridHelper.material.transparent = true;
    scene.add(gridHelper);

    // Lights
    const ambientLight = new THREE.AmbientLight(0x00ff66, 0.2);
    scene.add(ambientLight);

    const pointLight = new THREE.PointLight(0x00f0ff, 1.2, 150);
    pointLight.position.set(0, 30, 0);
    scene.add(pointLight);

    // Radar scan ring (expanding cylinder)
    const ringGeo = new THREE.RingGeometry(0.1, 2, 64);
    const ringMat = new THREE.MeshBasicMaterial({
        color: 0x00ff66,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.15,
        wireframe: true
    });
    scanRingMesh = new THREE.Mesh(ringGeo, ringMat);
    scanRingMesh.rotation.x = Math.PI / 2;
    scanRingMesh.position.y = -9.9;
    scene.add(scanRingMesh);

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
    const geo = new THREE.IcosahedronGeometry(3.5, 1);
    const mat = new THREE.MeshPhongMaterial({
        color: colors.gateway,
        emissive: colors.gateway,
        emissiveIntensity: 0.3,
        wireframe: true
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
    nodes.slice(1).forEach(node => {
        // remove extra shields if any
        if (node.shield) scene.remove(node.shield);
        scene.remove(node);
    });
    links.forEach(link => scene.remove(link));
    nodes = [nodes[0]];
    links = [];

    // Position devices in circle around gateway
    const radius = 30;
    const count = devices.length;

    devices.forEach((dev, i) => {
        const angle = (i / count) * Math.PI * 2;
        const x = Math.cos(angle) * radius;
        const z = Math.sin(angle) * radius;
        const y = (Math.random() - 0.5) * 4; // Slight variance in height

        // Determine node color
        let col = colors.clean;
        if (dev.exploited) {
            col = colors.exploited;
        } else if (dev.vulns && dev.vulns.length > 0) {
            col = colors.vulnerable;
        }

        // Host sphere
        const geo = new THREE.OctahedronGeometry(2, 1);
        const mat = new THREE.MeshPhongMaterial({
            color: col,
            emissive: col,
            emissiveIntensity: 0.1,
            flatShading: true,
            wireframe: false
        });
        const mesh = new THREE.Mesh(geo, mat);
        mesh.position.set(x, y, z);
        mesh.userData = dev; // Bind API device object to mesh data

        // Add wireframe outer shield for vulnerable/exploited nodes
        if (dev.exploited || (dev.vulns && dev.vulns.length > 0)) {
            const shieldGeo = new THREE.SphereGeometry(3, 16, 16);
            const shieldMat = new THREE.MeshBasicMaterial({
                color: col,
                wireframe: true,
                transparent: true,
                opacity: 0.25
            });
            const shieldMesh = new THREE.Mesh(shieldGeo, shieldMat);
            shieldMesh.position.set(x, y, z);
            scene.add(shieldMesh);
            mesh.shield = shieldMesh; // bind shield to node
        }

        scene.add(mesh);
        nodes.push(mesh);

        // Draw tactical dotted connection link to gateway
        const points = [];
        points.push(new THREE.Vector3(0, 0, 0));
        points.push(new THREE.Vector3(x, y, z));
        const lineGeo = new THREE.BufferGeometry().setFromPoints(points);
        const lineMat = new THREE.LineDashedMaterial({
            color: col,
            dashSize: 1.5,
            gapSize: 1,
            transparent: true,
            opacity: 0.5
        });
        const line = new THREE.Line(lineGeo, lineMat);
        line.computeLineDistances(); // Required for dashed lines
        scene.add(line);
        links.push(line);
    });
}

function onDocumentMouseDown(event) {
    event.preventDefault();

    const rect = renderer.domElement.getBoundingClientRect();
    mouse.x = ((event.clientX - rect.left) / container.clientWidth) * 2 - 1;
    mouse.y = -((event.clientY - rect.top) / container.clientHeight) * 2 + 1;

    raycaster.setFromCamera(mouse, camera);

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
            if (selectedNode.material.emissive) selectedNode.material.emissive.setHex(col);
        }

        selectedNode = clickedMesh;
        selectedNode.material.color.setHex(colors.selected);
        if (selectedNode.material.emissive) selectedNode.material.emissive.setHex(colors.selected);

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
    scene.rotation.y += 0.0008;

    // Slowly rotate gateway
    if (nodes[0]) {
        nodes[0].rotation.y += 0.005;
        nodes[0].rotation.z += 0.002;
    }

    // Pulse scale & rotation of other nodes
    const time = Date.now() * 0.003;
    nodes.forEach(node => {
        if (node.userData.ip === "Gateway") return;

        node.rotation.x += 0.01;
        node.rotation.y += 0.005;

        // Rotate its outer shield
        if (node.shield) {
            node.shield.rotation.y -= 0.005;
            node.shield.rotation.z += 0.002;
            const shieldScale = 1.0 + Math.sin(time * 0.5) * 0.08;
            node.shield.scale.set(shieldScale, shieldScale, shieldScale);
        }

        // Pulse size for vulnerable/exploited nodes
        if (node.userData.exploited || (node.userData.vulns && node.userData.vulns.length > 0)) {
            const scale = 1.0 + Math.sin(time) * 0.15;
            node.scale.set(scale, scale, scale);
        } else {
            node.scale.set(1.0, 1.0, 1.0);
        }
    });

    // Expand radar sweep ring
    if (scanRingMesh) {
        scanRingMesh.scale.x += 0.3;
        scanRingMesh.scale.y += 0.3;
        // Fade out as it expands
        scanRingMesh.material.opacity = Math.max(0, 0.25 - (scanRingMesh.scale.x / 140));

        if (scanRingMesh.scale.x > 75) {
            scanRingMesh.scale.set(1, 1, 1);
            scanRingMesh.material.opacity = 0.25;
        }
    }

    controls.update();
    renderer.render(scene, camera);
}

// Initialise
init3D();
