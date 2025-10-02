Rule 'Test.Simple' -Type 'System.IO.FileInfo' {
    $Assert.HasField($TargetObject, 'Name')
}
