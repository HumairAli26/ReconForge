// network3d.js
// ------------
// Three.js r128 3D topology — custom orbit controls (no OrbitControls module needed)

let scene, camera, renderer;
let nodes = [];
let links = [];
let scanRingMesh = null;
let raycaster, mouse;
let selectedNode = null;
let container = document.getElementById("three-canvas-holder");

// ── Custom orbit state ────────────────────────────────────────────────────────
const orbit = {
    isDragging: false,
    isPanning:  false,
    lastX: 0, lastY: 0,
    theta: 0.3,    // horizontal angle
    phi:   1.1,    // vertical angle  (clamped 0.2 – 1.5)
    radius: 80,    // distance
    target: new THREE.Vector3(0, 0, 0),
    damping: { theta: 0, phi: 0, radius: 0 }
};

// Color maps — Hacker Cyberpunk theme
const colors = {
    gateway:    0x00f0ff,
    clean:      0x00ff66,
    vulnerable: 0xffaa00,
    exploited:  0xff0055,
    selected:   0xd946ef,
    link:       0x00ff66,
    grid:       0x003311
};

// ── Init ──────────────────────────────────────────────────────────────────────
function init3D() {
    scene = new THREE.Scene();
    scene.background = new THREE.Color(0x010206);
    scene.fog = new THREE.FogExp2(0x010206, 0.007);

    camera = new THREE.PerspectiveCamera(60, container.clientWidth / container.clientHeight, 0.1, 1000);
    _updateCameraFromOrbit();

    renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setPixelRatio(window.devicePixelRatio);
    renderer.setSize(container.clientWidth, container.clientHeight);
    container.appendChild(renderer.domElement);

    // Grid floor
    const gridHelper = new THREE.GridHelper(200, 50, 0x00ff66, 0x002208);
    gridHelper.position.y = -10;
    gridHelper.material.opacity = 0.15;
    gridHelper.material.transparent = true;
    scene.add(gridHelper);

    // Ambient + point lights
    scene.add(new THREE.AmbientLight(0x00ff66, 0.2));
    const pointLight = new THREE.PointLight(0x00f0ff, 1.2, 150);
    pointLight.position.set(0, 30, 0);
    scene.add(pointLight);

    // Radar scan ring
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

    raycaster = new THREE.Raycaster();
    mouse = new THREE.Vector2();

    // Register all input events
    _registerEvents();

    createGateway();
    animate();
}

// ── Camera helper ─────────────────────────────────────────────────────────────
function _updateCameraFromOrbit() {
    const sinPhi   = Math.sin(orbit.phi);
    const cosPhi   = Math.cos(orbit.phi);
    const sinTheta = Math.sin(orbit.theta);
    const cosTheta = Math.cos(orbit.theta);
    camera.position.set(
        orbit.target.x + orbit.radius * sinPhi * sinTheta,
        orbit.target.y + orbit.radius * cosPhi,
        orbit.target.z + orbit.radius * sinPhi * cosTheta
    );
    camera.lookAt(orbit.target);
}

// ── Event registration ────────────────────────────────────────────────────────
function _registerEvents() {
    const el = renderer.domElement;

    // Mouse
    el.addEventListener("mousedown",  _onMouseDown);
    el.addEventListener("mousemove",  _onMouseMove);
    el.addEventListener("mouseup",    _onMouseUp);
    el.addEventListener("mouseleave", _onMouseUp);
    el.addEventListener("wheel",      _onWheel, { passive: false });
    el.addEventListener("click",      onNodeClick);
    el.addEventListener("contextmenu", e => e.preventDefault());

    // Touch
    el.addEventListener("touchstart",  _onTouchStart, { passive: false });
    el.addEventListener("touchmove",   _onTouchMove,  { passive: false });
    el.addEventListener("touchend",    _onTouchEnd);

    window.addEventListener("resize", onWindowResize);
}

// ── Mouse orbit / pan ─────────────────────────────────────────────────────────
function _onMouseDown(e) {
    if (e.button === 0) { orbit.isDragging = true; }
    if (e.button === 2) { orbit.isPanning  = true; }
    orbit.lastX = e.clientX;
    orbit.lastY = e.clientY;
}
function _onMouseMove(e) {
    const dx = e.clientX - orbit.lastX;
    const dy = e.clientY - orbit.lastY;
    orbit.lastX = e.clientX;
    orbit.lastY = e.clientY;
    if (orbit.isDragging) {
        orbit.theta -= dx * 0.005;
        orbit.phi    = Math.max(0.2, Math.min(1.55, orbit.phi + dy * 0.005));
        _updateCameraFromOrbit();
    }
    if (orbit.isPanning) {
        const panSpeed = orbit.radius * 0.001;
        const right = new THREE.Vector3();
        const up    = new THREE.Vector3();
        camera.getWorldDirection(new THREE.Vector3()); // ensure matrix fresh
        right.crossVectors(camera.getWorldDirection(new THREE.Vector3()), camera.up).normalize();
        up.copy(camera.up);
        orbit.target.addScaledVector(right, -dx * panSpeed);
        orbit.target.addScaledVector(up,     dy * panSpeed);
        _updateCameraFromOrbit();
    }
}
function _onMouseUp() {
    orbit.isDragging = false;
    orbit.isPanning  = false;
}
function _onWheel(e) {
    e.preventDefault();
    orbit.radius = Math.max(15, Math.min(150, orbit.radius + e.deltaY * 0.08));
    _updateCameraFromOrbit();
}

// ── Touch orbit (single = rotate, pinch = zoom) ───────────────────────────────
let _lastTouches = null;
function _onTouchStart(e) {
    e.preventDefault();
    _lastTouches = e.touches;
}
function _onTouchMove(e) {
    e.preventDefault();
    if (!_lastTouches) return;
    if (e.touches.length === 1 && _lastTouches.length === 1) {
        const dx = e.touches[0].clientX - _lastTouches[0].clientX;
        const dy = e.touches[0].clientY - _lastTouches[0].clientY;
        orbit.theta -= dx * 0.005;
        orbit.phi    = Math.max(0.2, Math.min(1.55, orbit.phi + dy * 0.005));
        _updateCameraFromOrbit();
    } else if (e.touches.length === 2 && _lastTouches.length === 2) {
        const prevDist = Math.hypot(
            _lastTouches[0].clientX - _lastTouches[1].clientX,
            _lastTouches[0].clientY - _lastTouches[1].clientY
        );
        const currDist = Math.hypot(
            e.touches[0].clientX - e.touches[1].clientX,
            e.touches[0].clientY - e.touches[1].clientY
        );
        orbit.radius = Math.max(15, Math.min(150, orbit.radius - (currDist - prevDist) * 0.15));
        _updateCameraFromOrbit();
    }
    _lastTouches = e.touches;
}
function _onTouchEnd() { _lastTouches = null; }

// ── Nodes ─────────────────────────────────────────────────────────────────────
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
        ip: "Gateway", mac: "N/A", hostname: "Router",
        vendor: "Gateway", device_type: "Network Device",
        risk: "Clean", open_ports: [], vulns: []
    };
    scene.add(mesh);
    nodes.push(mesh);
}

function updateNetworkTopology(devices) {
    // Remove old nodes (keep gateway at index 0)
    nodes.slice(1).forEach(node => {
        if (node.shield) scene.remove(node.shield);
        scene.remove(node);
    });
    links.forEach(link => scene.remove(link));
    nodes = [nodes[0]];
    links = [];

    const count  = devices.length;
    const radius = Math.max(28, 8 + count * 3.5);

    devices.forEach((dev, i) => {
        const angle = (i / count) * Math.PI * 2;
        const x = Math.cos(angle) * radius;
        const z = Math.sin(angle) * radius;
        const y = (Math.random() - 0.5) * 4;

        let col = colors.clean;
        if (dev.exploited)                          col = colors.exploited;
        else if (dev.vulns && dev.vulns.length > 0) col = colors.vulnerable;

        const geo = new THREE.OctahedronGeometry(2, 1);
        const mat = new THREE.MeshPhongMaterial({
            color: col, emissive: col,
            emissiveIntensity: 0.1, flatShading: true
        });
        const mesh = new THREE.Mesh(geo, mat);
        mesh.position.set(x, y, z);
        mesh.userData = dev;

        // Outer shield for threat nodes
        if (dev.exploited || (dev.vulns && dev.vulns.length > 0)) {
            const shieldGeo = new THREE.SphereGeometry(3, 16, 16);
            const shieldMat = new THREE.MeshBasicMaterial({
                color: col, wireframe: true, transparent: true, opacity: 0.25
            });
            const shield = new THREE.Mesh(shieldGeo, shieldMat);
            shield.position.set(x, y, z);
            scene.add(shield);
            mesh.shield = shield;
        }

        scene.add(mesh);
        nodes.push(mesh);

        // Dashed link to gateway
        const lineGeo = new THREE.BufferGeometry().setFromPoints([
            new THREE.Vector3(0, 0, 0),
            new THREE.Vector3(x, y, z)
        ]);
        const lineMat = new THREE.LineDashedMaterial({
            color: col, dashSize: 1.5, gapSize: 1, transparent: true, opacity: 0.5
        });
        const line = new THREE.Line(lineGeo, lineMat);
        line.computeLineDistances();
        scene.add(line);
        links.push(line);
    });
}

// ── Node click picking ────────────────────────────────────────────────────────
function onNodeClick(event) {
    const rect = renderer.domElement.getBoundingClientRect();
    mouse.x =  ((event.clientX - rect.left) / container.clientWidth)  * 2 - 1;
    mouse.y = -((event.clientY - rect.top)  / container.clientHeight) * 2 + 1;

    raycaster.setFromCamera(mouse, camera);
    const intersects = raycaster.intersectObjects(nodes);

    if (intersects.length > 0) {
        const hit = intersects[0].object;

        // Reset previous selection
        if (selectedNode) {
            let c = colors.clean;
            if (selectedNode.userData.ip === "Gateway") c = colors.gateway;
            else if (selectedNode.userData.exploited)    c = colors.exploited;
            else if (selectedNode.userData.vulns?.length) c = colors.vulnerable;
            selectedNode.material.color.setHex(c);
            if (selectedNode.material.emissive) selectedNode.material.emissive.setHex(c);
        }

        selectedNode = hit;
        selectedNode.material.color.setHex(colors.selected);
        if (selectedNode.material.emissive) selectedNode.material.emissive.setHex(colors.selected);

        if (typeof window.showHostDetails === "function") {
            window.showHostDetails(selectedNode.userData);
        }
    }
}

// ── Resize ────────────────────────────────────────────────────────────────────
function onWindowResize() {
    camera.aspect = container.clientWidth / container.clientHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(container.clientWidth, container.clientHeight);
}

// ── Animation loop ────────────────────────────────────────────────────────────
function animate() {
    requestAnimationFrame(animate);

    scene.rotation.y += 0.0008;

    if (nodes[0]) {
        nodes[0].rotation.y += 0.005;
        nodes[0].rotation.z += 0.002;
    }

    const time = Date.now() * 0.003;
    nodes.forEach(node => {
        if (node.userData.ip === "Gateway") return;
        node.rotation.x += 0.01;
        node.rotation.y += 0.005;

        if (node.shield) {
            node.shield.rotation.y -= 0.005;
            node.shield.rotation.z += 0.002;
            const ss = 1.0 + Math.sin(time * 0.5) * 0.08;
            node.shield.scale.set(ss, ss, ss);
        }

        if (node.userData.exploited || node.userData.vulns?.length) {
            const sc = 1.0 + Math.sin(time) * 0.15;
            node.scale.set(sc, sc, sc);
        } else {
            node.scale.set(1, 1, 1);
        }
    });

    // Radar sweep ring
    if (scanRingMesh) {
        scanRingMesh.scale.x += 0.3;
        scanRingMesh.scale.y += 0.3;
        scanRingMesh.material.opacity = Math.max(0, 0.25 - scanRingMesh.scale.x / 140);
        if (scanRingMesh.scale.x > 75) {
            scanRingMesh.scale.set(1, 1, 1);
            scanRingMesh.material.opacity = 0.25;
        }
    }

    renderer.render(scene, camera);
}

// Boot
init3D();
